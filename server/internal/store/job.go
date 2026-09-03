package store

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/certpilot/server/internal/domain"
	"github.com/jackc/pgx/v5"
)

type Job struct {
	ID          int64           `json:"id"`
	Kind        string          `json:"kind"`
	RefID       *int64          `json:"ref_id,omitempty"`
	State       string          `json:"state"`
	Stage       *string         `json:"stage,omitempty"`
	Attempt     int             `json:"attempt"`
	MaxAttempts int             `json:"max_attempts"`
	RunAfter    time.Time       `json:"run_after"`
	Payload     json.RawMessage `json:"payload"`
	LastError   *string         `json:"last_error,omitempty"`
	StartedAt   *time.Time      `json:"started_at,omitempty"`
	FinishedAt  *time.Time      `json:"finished_at,omitempty"`
	CreatedAt   time.Time       `json:"created_at"`
}

type JobLog struct {
	ID      int64     `json:"id"`
	JobID   int64     `json:"job_id"`
	Stage   string    `json:"stage"`
	Level   string    `json:"level"`
	Message string    `json:"message"`
	At      time.Time `json:"at"`
}

// EnqueueJob 投递一个任务。
func (s *Store) EnqueueJob(ctx context.Context, kind string, refID *int64, payload any) (int64, error) {
	blob := json.RawMessage(`{}`)
	if payload != nil {
		b, err := json.Marshal(payload)
		if err != nil {
			return 0, err
		}
		blob = b
	}
	var id int64
	err := s.pool.QueryRow(ctx, `
		INSERT INTO job (kind, ref_id, payload, stage) VALUES ($1,$2,$3,$4) RETURNING id`,
		kind, refID, blob, string(domain.StagePending)).Scan(&id)
	return id, err
}

// ClaimJob 领取一个到期的待办任务。
//
// FOR UPDATE SKIP LOCKED 让多个 worker 可以并发领取而不会拿到同一条，
// 这正是不需要 Redis 的原因——PostgreSQL 自己就是一个够用的队列。
func (s *Store) ClaimJob(ctx context.Context) (*Job, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var id int64
	err = tx.QueryRow(ctx, `
		SELECT id FROM job
		WHERE state = 'queued' AND run_after <= now()
		ORDER BY run_after
		FOR UPDATE SKIP LOCKED
		LIMIT 1`).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	var j Job
	err = tx.QueryRow(ctx, `
		UPDATE job SET state='running', attempt = attempt + 1, started_at = now()
		WHERE id = $1
		RETURNING id, kind, ref_id, state, stage, attempt, max_attempts,
		          run_after, payload, last_error, started_at, finished_at, created_at`, id).
		Scan(&j.ID, &j.Kind, &j.RefID, &j.State, &j.Stage, &j.Attempt, &j.MaxAttempts,
			&j.RunAfter, &j.Payload, &j.LastError, &j.StartedAt, &j.FinishedAt, &j.CreatedAt)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &j, nil
}

// SetStage 持久化流水线进度。进程重启后据此断点续跑，
// 而不是从头再向 CA 申请一张证书。
func (s *Store) SetStage(ctx context.Context, jobID int64, stage domain.Stage) error {
	_, err := s.pool.Exec(ctx, `UPDATE job SET stage=$2 WHERE id=$1`, jobID, string(stage))
	return err
}

func (s *Store) FinishJob(ctx context.Context, jobID int64, stage domain.Stage) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE job SET state='succeeded', stage=$2, finished_at=now() WHERE id=$1`,
		jobID, string(stage))
	return err
}

// FailJob 记录失败。可重试且未超次数时按指数退避重新入队，
// 否则置为终态失败并等待人工处理。
func (s *Store) FailJob(ctx context.Context, j *Job, cause string, class domain.RetryClass) error {
	if class == domain.RetryBackoff && j.Attempt < j.MaxAttempts {
		_, err := s.pool.Exec(ctx, `
			UPDATE job SET state='queued', last_error=$2, run_after=now() + $3::interval
			WHERE id=$1`, j.ID, cause, backoff(j.Attempt).String())
		return err
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE job SET state='failed', stage=$2, last_error=$3, finished_at=now() WHERE id=$1`,
		j.ID, string(domain.StageFailed), cause)
	return err
}

// backoff 是 1m / 5m / 30m / 2h… 的指数退避，上限 6 小时。
func backoff(attempt int) time.Duration {
	d := time.Minute * time.Duration(math.Pow(5, float64(attempt-1)))
	if d > 6*time.Hour || d <= 0 {
		return 6 * time.Hour
	}
	return d
}

// RequeueStaleJobs 把进程崩溃时留下的 running 任务放回队列。
// 启动时调用一次——没有它，一次意外重启会让任务永远卡在 running。
func (s *Store) RequeueStaleJobs(ctx context.Context, olderThan time.Duration) (int64, error) {
	ct, err := s.pool.Exec(ctx, `
		UPDATE job SET state='queued', run_after=now()
		WHERE state='running' AND started_at < now() - $1::interval`, olderThan.String())
	if err != nil {
		return 0, err
	}
	return ct.RowsAffected(), nil
}

func (s *Store) AppendLog(ctx context.Context, jobID int64, stage domain.Stage, level, msg string) (*JobLog, error) {
	var l JobLog
	err := s.pool.QueryRow(ctx, `
		INSERT INTO job_log (job_id, stage, level, message) VALUES ($1,$2,$3,$4)
		RETURNING id, job_id, stage, level, message, at`,
		jobID, string(stage), level, msg).
		Scan(&l.ID, &l.JobID, &l.Stage, &l.Level, &l.Message, &l.At)
	return &l, err
}

func (s *Store) ListJobs(ctx context.Context, limit int) ([]*Job, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, kind, ref_id, state, stage, attempt, max_attempts,
		       run_after, payload, last_error, started_at, finished_at, created_at
		FROM job ORDER BY id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Job{}
	for rows.Next() {
		var j Job
		if err := rows.Scan(&j.ID, &j.Kind, &j.RefID, &j.State, &j.Stage, &j.Attempt,
			&j.MaxAttempts, &j.RunAfter, &j.Payload, &j.LastError,
			&j.StartedAt, &j.FinishedAt, &j.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &j)
	}
	return out, rows.Err()
}

func (s *Store) GetJob(ctx context.Context, id int64) (*Job, error) {
	var j Job
	err := s.pool.QueryRow(ctx, `
		SELECT id, kind, ref_id, state, stage, attempt, max_attempts,
		       run_after, payload, last_error, started_at, finished_at, created_at
		FROM job WHERE id=$1`, id).
		Scan(&j.ID, &j.Kind, &j.RefID, &j.State, &j.Stage, &j.Attempt, &j.MaxAttempts,
			&j.RunAfter, &j.Payload, &j.LastError, &j.StartedAt, &j.FinishedAt, &j.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	return &j, err
}

func (s *Store) JobLogs(ctx context.Context, jobID int64) ([]*JobLog, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, job_id, stage, level, message, at FROM job_log
		WHERE job_id=$1 ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*JobLog{}
	for rows.Next() {
		var l JobLog
		if err := rows.Scan(&l.ID, &l.JobID, &l.Stage, &l.Level, &l.Message, &l.At); err != nil {
			return nil, err
		}
		out = append(out, &l)
	}
	return out, rows.Err()
}

// PruneJobs 按保留天数清理任务与日志，防止无限增长。
func (s *Store) PruneJobs(ctx context.Context, keepDays int) error {
	_, err := s.pool.Exec(ctx, `
		DELETE FROM job WHERE finished_at IS NOT NULL
		  AND finished_at < now() - make_interval(days => $1)`, keepDays)
	return err
}
