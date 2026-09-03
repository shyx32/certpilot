package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/certpilot/server/internal/notify"
	"github.com/certpilot/server/internal/secretbox"
	"github.com/jackc/pgx/v5"
)

// NotifyChannel 是一个通知渠道。配置里常含 Webhook token，因此加密存放。
type NotifyChannel struct {
	ID        int64     `json:"id"`
	Name      string    `json:"name"`
	Kind      string    `json:"kind"`
	Events    []string  `json:"events"`
	Enabled   bool      `json:"enabled"`
	CreatedAt time.Time `json:"created_at"`
}

func notifyAAD(id int64) []byte { return []byte(fmt.Sprintf("notify_channel:%d", id)) }

func (s *Store) CreateNotifyChannel(ctx context.Context, c *NotifyChannel, config []byte) (int64, error) {
	var id int64
	if err := s.pool.QueryRow(ctx, `SELECT nextval('notify_channel_id_seq')`).Scan(&id); err != nil {
		return 0, err
	}
	sealed, err := s.box.Seal(config, notifyAAD(id))
	if err != nil {
		return 0, err
	}
	blob, err := json.Marshal(sealed)
	if err != nil {
		return 0, err
	}
	events := c.Events
	if events == nil {
		events = []string{}
	}
	_, err = s.pool.Exec(ctx, `
		INSERT INTO notify_channel (id, name, kind, config_enc, events, enabled)
		VALUES ($1,$2,$3,$4,$5,$6)`, id, c.Name, c.Kind, blob, events, true)
	return id, err
}

func (s *Store) ListNotifyChannels(ctx context.Context) ([]*NotifyChannel, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT id, name, kind, events, enabled, created_at FROM notify_channel ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*NotifyChannel{}
	for rows.Next() {
		var c NotifyChannel
		if err := rows.Scan(&c.ID, &c.Name, &c.Kind, &c.Events, &c.Enabled, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, &c)
	}
	return out, rows.Err()
}

// NotifyConfig 解密并返回渠道配置。
func (s *Store) NotifyConfig(ctx context.Context, id int64) ([]byte, error) {
	var blob []byte
	err := s.pool.QueryRow(ctx, `SELECT config_enc FROM notify_channel WHERE id=$1`, id).Scan(&blob)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var sealed secretbox.Sealed
	if err := json.Unmarshal(blob, &sealed); err != nil {
		return nil, err
	}
	return s.box.Open(&sealed, notifyAAD(id))
}

func (s *Store) DeleteNotifyChannel(ctx context.Context, id int64) error {
	ct, err := s.pool.Exec(ctx, `DELETE FROM notify_channel WHERE id=$1`, id)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

// EnabledChannels 实现 notify.ChannelSource：返回启用渠道及其解密后的配置。
func (s *Store) EnabledChannels(ctx context.Context) ([]notify.ChannelSpec, error) {
	list, err := s.ListNotifyChannels(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]notify.ChannelSpec, 0, len(list))
	for _, c := range list {
		if !c.Enabled {
			continue
		}
		cfg, err := s.NotifyConfig(ctx, c.ID)
		if err != nil {
			// 单个渠道配置解不开不该拖垮其余渠道。
			continue
		}
		out = append(out, notify.ChannelSpec{
			ID: c.ID, Name: c.Name, Kind: c.Kind, Events: c.Events, Config: cfg,
		})
	}
	return out, nil
}
