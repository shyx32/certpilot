import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link, useParams } from "react-router-dom";
import { PlayCircle } from "lucide-react";
import { api, type Binding, type CertConfig, type CertVersion } from "@/lib/api";
import { certStatus, formatDate, formatTime } from "@/lib/format";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

// 流水线的九个状态。终点是 verified 而不是 issued——
// 证书签出来了但线上没换，不算完成。
const STAGES = [
  { key: "preflight", label: "前置检查" },
  { key: "ordering", label: "创建 Order" },
  { key: "challenging", label: "投放验证" },
  { key: "validating", label: "CA 校验" },
  { key: "finalizing", label: "下载证书" },
  { key: "issued", label: "已签发" },
  { key: "deploying", label: "部署" },
  { key: "verified", label: "已生效" },
];

export function CertificateDetail() {
  const { id } = useParams();
  const qc = useQueryClient();

  const cert = useQuery({
    queryKey: ["cert", id],
    queryFn: () => api.get<CertConfig>(`/certificates/${id}`),
  });
  const bindings = useQuery({
    queryKey: ["cert-bindings", id],
    queryFn: () => api.get<Binding[]>(`/certificates/${id}/bindings`),
  });
  const versions = useQuery({
    queryKey: ["cert-versions", id],
    queryFn: () => api.get<CertVersion[]>(`/certificates/${id}/versions`),
  });

  const issue = useMutation({
    mutationFn: () => api.post<{ job_id: number }>(`/certificates/${id}/issue`),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["jobs"] });
      qc.invalidateQueries({ queryKey: ["cert", id] });
    },
  });

  if (cert.isLoading) return <Loading />;
  if (cert.error) return <ErrorNote error={cert.error} onRetry={() => cert.refetch()} />;
  const c = cert.data!;
  const s = certStatus(c);

  return (
    <>
      <div className="mb-5 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0 space-y-0.5">
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-semibold tracking-tight">{c.name}</h1>
            <StatusBadge state={s.state}>{s.text}</StatusBadge>
          </div>
          <p className="text-muted-foreground text-sm">{c.domains.join(" · ")}</p>
        </div>
        <div className="flex items-center gap-2">
          {issue.data && (
            <Link to={`/jobs/${issue.data.job_id}`} className="text-xs underline underline-offset-2">
              查看任务 #{issue.data.job_id}
            </Link>
          )}
          <Button size="sm" disabled={issue.isPending} onClick={() => issue.mutate()}>
            <PlayCircle className="size-3.5" />
            {issue.isPending ? "已提交…" : "立即续期"}
          </Button>
        </div>
      </div>

      {issue.error && <div className="mb-4"><ErrorNote error={issue.error} /></div>}

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Info label="到期时间" value={formatDate(c.not_after)} />
        <Info label="剩余天数" value={c.days_left == null ? "尚未签发" : `${c.days_left} 天`} />
        <Info label="验证方式" value={c.challenge_type} />
        <Info label="密钥算法" value={c.key_type} />
      </div>

      {c.fail_streak > 0 && (
        <div className="bg-warn-soft text-warn mb-4 rounded-md border border-warn/30 p-3 text-sm">
          已连续失败 {c.fail_streak} 次
          {c.cooldown_until && `，冷却至 ${formatTime(c.cooldown_until)}`}。
          连续失败会进入冷却，避免把 CA 的失败配额浪费在同一个问题上。点「立即续期」可解除冷却重试。
        </div>
      )}

      <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle>签发流程</CardTitle>
          <CardDescription>终点是「已生效」而不是「已签发」——签出来了但线上没换，不算完成。</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 gap-1.5 sm:grid-cols-8">
            {STAGES.map((st, i) => (
              <div key={st.key} className="bg-muted rounded-md px-2 py-2 text-center">
                <div className="text-muted-foreground font-mono text-[10px] leading-none">
                  {String(i + 1).padStart(2, "0")}
                </div>
                <div className="mt-1 text-xs font-medium">{st.label}</div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>部署目标</CardTitle>
          <CardDescription>「已生效」表示外部拨测确认线上指纹与本地最新版一致。</CardDescription>
        </CardHeader>
        <CardContent className="px-0 pt-1">
          {bindings.isLoading ? (
            <Loading />
          ) : !bindings.data?.length ? (
            <Empty title="没有绑定部署目标" hint="证书会正常签发并保存在库中，但不会自动推送到任何地方。" />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>目标</TH>
                  <TH>类型</TH>
                  <TH className="w-full">状态</TH>
                  <TH>最后部署</TH>
                </TR>
              </THead>
              <TBody>
                {bindings.data.map((b) => (
                  <TR key={b.id}>
                    <TD className="font-medium whitespace-nowrap">{b.target_name}</TD>
                    <TD className="text-xs whitespace-nowrap">{b.target_kind}</TD>
                    <TD>
                      <StatusBadge
                        state={
                          b.last_status === "verified" ? "ok"
                          : b.last_status === "failed" ? "danger"
                          : b.last_status === "deployed" ? "warn" : "busy"
                        }
                      >
                        {b.last_status === "verified" ? "已生效"
                          : b.last_status === "deployed" ? "已下发待确认"
                          : b.last_status === "failed" ? "失败" : "待部署"}
                      </StatusBadge>
                      {b.last_error && (
                        <div className="text-muted-foreground mt-1 line-clamp-2 text-xs" title={b.last_error}>
                          {b.last_error}
                        </div>
                      )}
                    </TD>
                    <TD className="text-xs whitespace-nowrap">{formatTime(b.last_deployed_at)}</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>历史版本</CardTitle>
          <CardDescription>保留最近 5 版，用于回滚与追溯线上跑的是哪一版。</CardDescription>
        </CardHeader>
        <CardContent className="px-0 pt-1">
          {versions.isLoading ? (
            <Loading />
          ) : !versions.data?.length ? (
            <Empty title="还没有签发过" hint="点右上角「立即续期」触发第一次签发。" />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>签发时间</TH>
                  <TH>有效期至</TH>
                  <TH>颁发者</TH>
                  <TH className="w-full">指纹</TH>
                </TR>
              </THead>
              <TBody>
                {versions.data.map((v) => (
                  <TR key={v.id}>
                    <TD className="text-xs whitespace-nowrap">{formatTime(v.created_at)}</TD>
                    <TD className="text-xs whitespace-nowrap">{formatDate(v.not_after)}</TD>
                    <TD className="text-xs">{v.issuer}</TD>
                    <TD className="font-mono text-xs">{v.fingerprint.slice(0, 16)}…</TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>
      </div>
    </>
  );
}

function Info({ label, value }: { label: string; value: string }) {
  return (
    <div className="bg-card rounded-lg border px-4 py-3.5 shadow-xs">
      <div className="text-muted-foreground text-xs font-medium">{label}</div>
      <div className="mt-1 text-sm font-semibold">{value}</div>
    </div>
  );
}
