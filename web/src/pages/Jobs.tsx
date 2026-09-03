import { useEffect, useRef, useState } from "react";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { api, type Job, type JobLog } from "@/lib/api";
import { useEvents } from "@/hooks/useEvents";
import { formatTime, jobStatus, stageName } from "@/lib/format";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

export function Jobs() {
  const qc = useQueryClient();
  const q = useQuery({ queryKey: ["jobs"], queryFn: () => api.get<Job[]>("/jobs") });

  // 任务状态变化时刷新列表；日志刷屏不触发，避免列表反复抖动。
  useEvents((e) => {
    if (e.type === "job_state") qc.invalidateQueries({ queryKey: ["jobs"] });
  });

  return (
    <>
      <PageHeader title="任务与日志" description="签发是分钟级的长流程，进度会实时推送。" />

      <Card>
        <CardContent className="px-0 py-1">
          {q.isLoading ? (
            <Loading />
          ) : q.error ? (
            <div className="p-5"><ErrorNote error={q.error} onRetry={() => q.refetch()} /></div>
          ) : q.data!.length === 0 ? (
            <Empty title="还没有任务" hint="调度器每小时扫描一次到期证书；也可以在证书详情页点「立即续期」手工触发。" />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>#</TH>
                  <TH>类型</TH>
                  <TH>阶段</TH>
                  <TH className="text-right">尝试</TH>
                  <TH className="w-full">状态</TH>
                  <TH>开始时间</TH>
                </TR>
              </THead>
              <TBody>
                {q.data!.map((j) => {
                  const s = jobStatus(j);
                  return (
                    <TR key={j.id}>
                      <TD className="tabular font-medium whitespace-nowrap">
                        <Link to={`/jobs/${j.id}`} className="hover:underline">#{j.id}</Link>
                      </TD>
                      <TD className="text-xs whitespace-nowrap">{j.kind}</TD>
                      <TD className="text-xs whitespace-nowrap">{stageName(j.stage)}</TD>
                      <TD className="tabular text-right text-xs">{j.attempt}/{j.max_attempts}</TD>
                      <TD>
                        <StatusBadge state={s.state}>{s.text}</StatusBadge>
                        {j.last_error && (
                          <div className="text-muted-foreground mt-1 line-clamp-2 text-xs" title={j.last_error}>
                            {j.last_error}
                          </div>
                        )}
                      </TD>
                      <TD className="text-xs whitespace-nowrap">{formatTime(j.started_at)}</TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </>
  );
}

const levelStyles: Record<string, string> = {
  error: "text-danger",
  warn: "text-warn",
  info: "text-foreground",
};

export function JobDetail() {
  const { id } = useParams();
  const jobID = Number(id);
  const [live, setLive] = useState<JobLog[]>([]);
  const [autoScroll, setAutoScroll] = useState(true);
  const bottom = useRef<HTMLDivElement>(null);

  const job = useQuery({ queryKey: ["job", id], queryFn: () => api.get<Job>(`/jobs/${id}`) });
  // 首次加载拉全量；WebSocket 只负责增量。两者配合才不会缺片段。
  const logs = useQuery({ queryKey: ["job-logs", id], queryFn: () => api.get<JobLog[]>(`/jobs/${id}/logs`) });

  useEvents((e) => {
    if (e.job_id !== jobID) return;
    if (e.type === "job_log") {
      setLive((prev) => [
        ...prev,
        {
          id: -prev.length - 1,
          job_id: jobID,
          stage: e.stage ?? "",
          level: e.level ?? "info",
          message: e.message ?? "",
          at: e.at ?? new Date().toISOString(),
        },
      ]);
    } else if (e.type === "job_state") {
      job.refetch();
    }
  });

  const all = [...(logs.data ?? []), ...live];

  useEffect(() => {
    if (autoScroll) bottom.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [all.length, autoScroll]);

  if (job.isLoading) return <Loading />;
  if (job.error) return <ErrorNote error={job.error} onRetry={() => job.refetch()} />;
  const j = job.data!;
  const s = jobStatus(j);

  return (
    <>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-0.5">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight">任务 #{j.id}</h1>
            <StatusBadge state={s.state}>{s.text}</StatusBadge>
          </div>
          <p className="text-muted-foreground text-sm">
            {j.kind} · 当前阶段 {stageName(j.stage)} · 第 {j.attempt}/{j.max_attempts} 次尝试
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          onClick={() => navigator.clipboard?.writeText(all.map((l) => `[${l.level}] ${l.stage} ${l.message}`).join("\n"))}
        >
          复制全部日志
        </Button>
      </div>

      {j.last_error && <div className="mb-4"><ErrorNote error={new Error(j.last_error)} /></div>}

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <div className="flex flex-col gap-1">
              <CardTitle>执行日志</CardTitle>
              <CardDescription>实时推送，断线会自动重连。</CardDescription>
            </div>
            <label className="text-muted-foreground flex items-center gap-1.5 text-xs">
              <input type="checkbox" checked={autoScroll} onChange={(e) => setAutoScroll(e.target.checked)} />
              自动滚动
            </label>
          </div>
        </CardHeader>
        <CardContent>
          {logs.isLoading ? (
            <Loading />
          ) : all.length === 0 ? (
            <Empty title="还没有日志" hint="任务开始执行后，每一步都会实时出现在这里。" />
          ) : (
            <div className="bg-muted/40 max-h-[28rem] overflow-y-auto rounded-md border p-3 font-mono text-xs">
              {all.map((l, i) => (
                <div key={`${l.id}-${i}`} className="flex gap-2 py-0.5">
                  <span className="text-muted-foreground shrink-0">{formatTime(l.at).slice(-8)}</span>
                  <span className="text-muted-foreground w-20 shrink-0">{l.stage}</span>
                  <span className={levelStyles[l.level] ?? ""}>{l.message}</span>
                </div>
              ))}
              <div ref={bottom} />
            </div>
          )}
        </CardContent>
      </Card>
    </>
  );
}
