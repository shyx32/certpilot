import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RefreshCw, Search, Trash2 } from "lucide-react";
import {
  api, type HealthCheck, type MonitorDomain, type ProbeResult,
} from "@/lib/api";
import { formatDate, formatTime } from "@/lib/format";
import { PageHeader, Stat } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";
import type { CertState } from "@/lib/utils";

const sevState: Record<string, CertState> = {
  danger: "danger",
  warn: "warn",
  info: "busy",
  "": "ok",
};

const sevLabel: Record<string, string> = {
  danger: "严重",
  warn: "警告",
  info: "提示",
  "": "正常",
};

export function Health() {
  const qc = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [probeOpen, setProbeOpen] = useState(false);

  const q = useQuery({
    queryKey: ["health"],
    queryFn: () => api.get<HealthCheck[]>("/health-checks"),
  });
  const monitors = useQuery({
    queryKey: ["monitors"],
    queryFn: () => api.get<MonitorDomain[]>("/monitors"),
  });

  const scan = useMutation({
    mutationFn: () => api.post("/health-checks/scan"),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["jobs"] }),
  });
  const removeMonitor = useMutation({
    mutationFn: (id: number) => api.del(`/monitors/${id}`),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["monitors"] }),
  });

  const rows = q.data ?? [];
  const counts = {
    danger: rows.filter((r) => r.severity === "danger").length,
    warn: rows.filter((r) => r.severity === "warn").length,
    ok: rows.filter((r) => r.severity === "" || r.severity === "info").length,
  };

  return (
    <>
      <PageHeader
        title="巡检看板"
        description="每天连上去看一眼线上到底跑着哪张证书——这是签发系统自己回答不了的问题。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => setProbeOpen(true)}>
              <Search className="size-3.5" />
              即时拨测
            </Button>
            <Button variant="outline" size="sm" onClick={() => setAddOpen(true)}>
              <Plus className="size-3.5" />
              添加监控域名
            </Button>
            <Button size="sm" disabled={scan.isPending} onClick={() => scan.mutate()}>
              <RefreshCw className="size-3.5" />
              {scan.isPending ? "已提交…" : "立即巡检"}
            </Button>
          </>
        }
      />

      {scan.error && <div className="mb-4"><ErrorNote error={scan.error} /></div>}
      {scan.isSuccess && (
        <div className="bg-ok-soft text-ok mb-4 rounded-md border border-ok/30 p-3 text-sm">
          巡检任务已提交，结果会在完成后出现在下面。可在「任务与日志」里看进度。
        </div>
      )}

      <div className="mb-4 grid gap-3 sm:grid-cols-3">
        <Stat label="正常" value={counts.ok} hint="最近一次巡检" />
        <Stat label="警告" value={counts.warn} hint="需要安排处理" tone={counts.warn > 0 ? "warn" : undefined} />
        <Stat label="严重" value={counts.danger} hint="需要立即处理" tone={counts.danger > 0 ? "danger" : undefined} />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>域名健康</CardTitle>
          <CardDescription>按严重程度排序，需要处理的排在最前。</CardDescription>
        </CardHeader>
        <CardContent className="px-0 pt-1">
          {q.isLoading ? (
            <Loading />
          ) : q.error ? (
            <div className="px-5 pb-4"><ErrorNote error={q.error} onRetry={() => q.refetch()} /></div>
          ) : rows.length === 0 ? (
            <Empty
              title="还没有巡检结果"
              hint="巡检每天自动跑一次。也可以点右上角「立即巡检」马上触发一轮。"
              action={<Button size="sm" onClick={() => scan.mutate()}>立即巡检</Button>}
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>域名</TH>
                  <TH>状态</TH>
                  <TH className="w-full">发现</TH>
                  <TH className="text-right">剩余</TH>
                  <TH>到期</TH>
                  <TH>检查时间</TH>
                </TR>
              </THead>
              <TBody>
                {rows.map((h) => (
                  <TR key={h.id}>
                    <TD className="font-medium whitespace-nowrap">
                      {h.domain}
                      {h.port !== 443 && <span className="text-muted-foreground">:{h.port}</span>}
                      {h.issuer && (
                        <div className="text-muted-foreground text-xs font-normal">{h.issuer}</div>
                      )}
                    </TD>
                    <TD>
                      <StatusBadge state={sevState[h.severity] ?? "warn"}>
                        {sevLabel[h.severity] ?? h.severity}
                      </StatusBadge>
                    </TD>
                    <TD className="text-xs">
                      {h.findings?.length ? (
                        <ul className="space-y-0.5">
                          {h.findings.map((f, i) => (
                            <li
                              key={i}
                              className={
                                f.severity === "danger" ? "text-danger"
                                : f.severity === "warn" ? "text-warn"
                                : "text-muted-foreground"
                              }
                            >
                              {f.text}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TD>
                    <TD className="tabular text-right whitespace-nowrap">
                      {h.days_left == null ? "—" : `${h.days_left} 天`}
                    </TD>
                    <TD className="text-xs whitespace-nowrap">{formatDate(h.not_after)}</TD>
                    <TD className="text-muted-foreground text-xs whitespace-nowrap">
                      {formatTime(h.checked_at)}
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {!!monitors.data?.length && (
        <Card className="mt-4">
          <CardHeader>
            <CardTitle>仅监控的域名</CardTitle>
            <CardDescription>
              证书不是本系统签的（别人管的、买的商业证书），但到期前仍然希望有人知道。
            </CardDescription>
          </CardHeader>
          <CardContent className="px-0 pt-1">
            <Table>
              <THead>
                <TR><TH>域名</TH><TH>端口</TH><TH className="w-full">备注</TH><TH className="w-px" /></TR>
              </THead>
              <TBody>
                {monitors.data.map((m) => (
                  <TR key={m.id}>
                    <TD className="font-medium whitespace-nowrap">{m.domain}</TD>
                    <TD className="tabular text-xs">{m.port}</TD>
                    <TD className="text-muted-foreground text-xs">{m.note ?? "—"}</TD>
                    <TD>
                      <Button variant="ghost" size="sm"
                        onClick={() => confirm(`不再监控 ${m.domain}？`) && removeMonitor.mutate(m.id)}>
                        <Trash2 className="text-danger size-3.5" />
                      </Button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <AddMonitorDialog
        open={addOpen}
        onClose={() => setAddOpen(false)}
        onDone={() => qc.invalidateQueries({ queryKey: ["monitors"] })}
      />
      <ProbeDialog open={probeOpen} onClose={() => setProbeOpen(false)} />
    </>
  );
}

function AddMonitorDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({ domain: "", port: 443, note: "" });
  const m = useMutation({
    mutationFn: () => api.post("/monitors", form),
    onSuccess: () => { onDone(); onClose(); },
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="添加监控域名"
      description="只监控到期与健康，不参与签发。"
    >
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <Field label="域名">
          <Input value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })}
            placeholder="legacy.example.com" required />
        </Field>
        <Field label="端口">
          <Input type="number" value={form.port}
            onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} />
        </Field>
        <Field label="备注" hint="例如「供应商提供的商业证书，到期需联系他们」。">
          <Input value={form.note} onChange={(e) => setForm({ ...form, note: e.target.value })} />
        </Field>
        {m.error && <ErrorNote error={m.error} />}
        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button type="submit" disabled={m.isPending}>{m.isPending ? "保存中…" : "保存"}</Button>
        </div>
      </form>
    </Dialog>
  );
}

function ProbeDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [domain, setDomain] = useState("");
  const [res, setRes] = useState<ProbeResult>();

  const m = useMutation({
    mutationFn: () => api.post<ProbeResult>("/health-checks/probe", { domain }),
    onSuccess: setRes,
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="即时拨测"
      description="现在连上去看一眼，结果不写入巡检历史。"
      className="max-w-xl"
    >
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <Field label="域名">
          <Input value={domain} onChange={(e) => { setDomain(e.target.value); setRes(undefined); }}
            placeholder="example.com" required />
        </Field>
        {m.error && <ErrorNote error={m.error} />}

        {res && (
          <div className="space-y-3 rounded-md border p-3 text-xs">
            <div className="grid gap-2 sm:grid-cols-2">
              <Kv label="主体" value={res.subject} />
              <Kv label="颁发者" value={res.issuer} />
              <Kv label="到期" value={`${formatDate(res.not_after)}（${res.days_left} 天）`} />
              <Kv label="协议" value={res.tls_version} />
              <Kv label="链长度" value={String(res.chain_len)} />
              <Kv label="域名匹配" value={res.name_match ? "是" : "否"} />
            </div>
            {res.sans?.length > 0 && <Kv label="覆盖域名" value={res.sans.join(", ")} />}
            {res.issues?.length ? (
              <ul className="space-y-1">
                {res.issues.map((f, i) => (
                  <li key={i} className={f.severity === "danger" ? "text-danger" : "text-warn"}>
                    {f.text}
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-ok">没有发现问题。</p>
            )}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>关闭</Button>
          <Button type="submit" disabled={m.isPending}>{m.isPending ? "拨测中…" : "拨测"}</Button>
        </div>
      </form>
    </Dialog>
  );
}

function Kv({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <span className="text-muted-foreground">{label}：</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
