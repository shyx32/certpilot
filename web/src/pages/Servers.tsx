import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, RadioTower, Trash2, TerminalSquare } from "lucide-react";
import {
  api, type DetectResult, type DryRunResult, type ServerService, type SSHHost,
} from "@/lib/api";
import { formatTime } from "@/lib/format";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Field, Input, Textarea } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

const kindLabels: Record<ServerService["kind"], string> = {
  nginx_systemd: "宿主机 · systemd",
  nginx_bare: "宿主机 · 直接管理",
  nginx_docker: "Docker 容器",
};

const strategyLabels: Record<ServerService["write_strategy"], string> = {
  host: "直写宿主机",
  host_sudo: "sudo 写入",
  helper: "辅助容器写入",
};

export function Servers() {
  const qc = useQueryClient();
  const [addOpen, setAddOpen] = useState(false);
  const [expanded, setExpanded] = useState<number | null>(null);

  const hosts = useQuery({ queryKey: ["servers"], queryFn: () => api.get<SSHHost[]>("/servers") });
  const refresh = () => {
    qc.invalidateQueries({ queryKey: ["servers"] });
    qc.invalidateQueries({ queryKey: ["services"] });
  };

  const detect = useMutation({
    mutationFn: (id: number) => api.post<DetectResult>(`/servers/${id}/detect`),
    onSuccess: (_, id) => {
      refresh();
      setExpanded(id);
    },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/servers/${id}`),
    onSuccess: refresh,
  });

  return (
    <>
      <PageHeader
        title="服务器"
        description="探测目标机上的 nginx 形态，证书签发后自动下发并重载。"
        actions={
          <Button size="sm" onClick={() => setAddOpen(true)}>
            <Plus className="size-3.5" />
            添加服务器
          </Button>
        }
      />

      {detect.error && <div className="mb-4"><ErrorNote error={detect.error} /></div>}

      <Card>
        <CardContent className="px-0 py-1">
          {hosts.isLoading ? (
            <Loading />
          ) : hosts.error ? (
            <div className="p-5"><ErrorNote error={hosts.error} onRetry={() => hosts.refetch()} /></div>
          ) : hosts.data!.length === 0 ? (
            <Empty
              title="还没有服务器"
              hint="添加一台跑着 nginx 的机器，系统会自动认出它的运行形态，并找出配置里已有的证书。"
              action={<Button size="sm" onClick={() => setAddOpen(true)}>添加服务器</Button>}
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>名称</TH>
                  <TH>地址</TH>
                  <TH className="text-right">服务</TH>
                  <TH className="w-full">最后探测</TH>
                  <TH className="w-px" />
                </TR>
              </THead>
              <TBody>
                {hosts.data!.map((h) => (
                  <TR key={h.id}>
                    <TD className="font-medium whitespace-nowrap">
                      <button
                        className="hover:underline"
                        onClick={() => setExpanded(expanded === h.id ? null : h.id)}
                      >
                        {h.name}
                      </button>
                    </TD>
                    <TD className="text-muted-foreground font-mono text-xs whitespace-nowrap">
                      {h.username}@{h.host}:{h.port}
                    </TD>
                    <TD className="tabular text-right">{h.service_count}</TD>
                    <TD>
                      {h.last_probe_ok == null ? (
                        <StatusBadge state="busy">未探测</StatusBadge>
                      ) : h.last_probe_ok ? (
                        <div className="flex items-center gap-2">
                          <StatusBadge state="ok">正常</StatusBadge>
                          <span className="text-muted-foreground text-xs">{formatTime(h.last_probe_at)}</span>
                        </div>
                      ) : (
                        <div className="flex flex-col items-start gap-1">
                          <StatusBadge state="danger">失败</StatusBadge>
                          <span className="text-muted-foreground line-clamp-2 text-xs" title={h.last_probe_err}>
                            {h.last_probe_err}
                          </span>
                        </div>
                      )}
                    </TD>
                    <TD>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          title="探测 nginx 形态"
                          disabled={detect.isPending}
                          onClick={() => detect.mutate(h.id)}
                        >
                          <RadioTower className="size-3.5" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="sm"
                          title="删除"
                          onClick={() => confirm(`删除服务器「${h.name}」？绑定它的部署目标将失效。`) && remove.mutate(h.id)}
                        >
                          <Trash2 className="text-danger size-3.5" />
                        </Button>
                      </div>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>

      {expanded != null && <ServiceList hostID={expanded} />}

      <AddDialog open={addOpen} onClose={() => setAddOpen(false)} onDone={refresh} />
    </>
  );
}

function ServiceList({ hostID }: { hostID: number }) {
  const q = useQuery({
    queryKey: ["services", hostID],
    queryFn: () => api.get<ServerService[]>(`/services?host_id=${hostID}`),
  });

  if (q.isLoading) return <Loading label="读取服务" />;
  if (q.error) return <div className="mt-4"><ErrorNote error={q.error} /></div>;
  if (!q.data!.length) {
    return (
      <Card className="mt-4">
        <CardContent>
          <Empty title="这台机器上没有探测到 nginx" hint="点服务器行右侧的探测按钮试一次，或确认登录用户有权限执行 nginx 与 docker。" />
        </CardContent>
      </Card>
    );
  }

  return (
    <div className="mt-4 space-y-4">
      {q.data!.map((s) => <ServiceCard key={s.id} svc={s} />)}
    </div>
  );
}

function ServiceCard({ svc }: { svc: ServerService }) {
  const [dry, setDry] = useState<DryRunResult>();
  const run = useMutation({
    mutationFn: () => api.post<DryRunResult>(`/services/${svc.id}/dry-run`),
    onSuccess: setDry,
  });

  const title = svc.compose_service
    ? `${svc.compose_project} / ${svc.compose_service}`
    : (svc.container_name ?? kindLabels[svc.kind]);

  return (
    <Card>
      <CardHeader>
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 space-y-0.5">
            <CardTitle className="flex flex-wrap items-center gap-2">
              {title}
              <span className="bg-muted text-muted-foreground rounded px-1.5 py-0.5 text-[11px] font-normal">
                {kindLabels[svc.kind]}
              </span>
            </CardTitle>
            <CardDescription>
              {strategyLabels[svc.write_strategy]}
              {svc.strategy_reason && ` · ${svc.strategy_reason}`}
            </CardDescription>
          </div>
          <Button variant="outline" size="sm" disabled={run.isPending} onClick={() => run.mutate()}>
            <TerminalSquare className="size-3.5" />
            {run.isPending ? "执行中…" : "试运行"}
          </Button>
        </div>
      </CardHeader>

      <CardContent className="space-y-3 pt-1">
        {svc.notes?.length > 0 && (
          <div className="bg-warn-soft text-warn space-y-1 rounded-md border border-warn/30 p-3 text-xs">
            {svc.notes.map((n, i) => <p key={i}>{n}</p>)}
          </div>
        )}

        <div className="grid gap-3 sm:grid-cols-2">
          <Cmd label="预检命令" argv={svc.test_argv} sudo={svc.reload_needs_sudo} />
          <Cmd label="重载命令" argv={svc.reload_argv} sudo={svc.reload_needs_sudo} />
        </div>

        {svc.discovered_certs?.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-xs font-medium">配置里已有的证书</div>
            <div className="overflow-x-auto rounded-md border">
              <table className="w-full text-xs">
                <tbody>
                  {svc.discovered_certs.map((c) => (
                    <tr key={c.CertPath} className="border-b last:border-0">
                      <td className="px-3 py-2 font-mono whitespace-nowrap">{c.CertPath}</td>
                      <td className="text-muted-foreground px-3 py-2">{c.Domains.join(", ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <p className="text-muted-foreground text-xs">
              这些是从 <code>nginx -T</code> 里读出来的。创建证书时填上同样的路径，续期后会自动替换。
            </p>
          </div>
        )}

        {svc.mounts?.length > 0 && (
          <details className="text-xs">
            <summary className="text-muted-foreground cursor-pointer">挂载映射（{svc.mounts.length}）</summary>
            <div className="mt-2 space-y-1 font-mono">
              {svc.mounts.map((m) => (
                <div key={m.Destination} className="text-muted-foreground">
                  {m.Destination} ← {m.Source}
                  <span className="ml-1.5">[{m.Type}{m.RW ? "" : ",ro"}]</span>
                </div>
              ))}
            </div>
          </details>
        )}

        {run.error && <ErrorNote error={run.error} />}
        {dry && (
          <div className="space-y-1.5">
            <div className="flex items-center gap-2">
              <StatusBadge state={dry.ok ? "ok" : "danger"}>
                {dry.ok ? "预检通过" : "预检未通过"}
              </StatusBadge>
              {dry.command && (
                <code className="text-muted-foreground text-xs">{dry.command.join(" ")}</code>
              )}
            </div>
            <pre className="bg-muted/40 max-h-48 overflow-auto rounded-md border p-2.5 font-mono text-xs whitespace-pre-wrap">
              {dry.output || "（无输出）"}
            </pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function Cmd({ label, argv, sudo }: { label: string; argv: string[]; sudo?: boolean }) {
  return (
    <div className="space-y-1">
      <div className="text-muted-foreground text-xs font-medium">{label}</div>
      <code className="bg-muted block overflow-x-auto rounded px-2 py-1.5 font-mono text-xs">
        {argv?.length ? (sudo ? "sudo -n " : "") + argv.join(" ") : "（未配置）"}
      </code>
    </div>
  );
}

function AddDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({
    name: "", host: "", port: 22, username: "root", private_key_pem: "", password: "",
  });

  const m = useMutation({
    mutationFn: () => api.post("/servers", form),
    onSuccess: () => { onDone(); onClose(); },
  });

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="添加服务器"
      description="保存后点探测按钮，系统会自动认出 nginx 的运行形态。"
      className="max-w-xl"
    >
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="名称">
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="web-01" required />
          </Field>
          <Field label="地址">
            <Input value={form.host} onChange={(e) => setForm({ ...form, host: e.target.value })} placeholder="10.0.0.12" required />
          </Field>
          <Field label="端口">
            <Input type="number" value={form.port} onChange={(e) => setForm({ ...form, port: Number(e.target.value) })} />
          </Field>
          <Field label="登录用户">
            <Input value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} required />
          </Field>
        </div>

        <Field
          label="SSH 私钥"
          hint="加密存放。推荐用密钥而非密码；首次连接时会记下主机指纹，之后不匹配即拒绝连接。"
        >
          <Textarea
            rows={5}
            value={form.private_key_pem}
            onChange={(e) => setForm({ ...form, private_key_pem: e.target.value })}
            placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"
          />
        </Field>

        <Field label="或使用密码" hint="仅在没有密钥时使用。">
          <Input type="password" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
        </Field>

        <div className="bg-muted text-muted-foreground rounded-md p-3 text-xs">
          登录用户需要能写证书目录。如果 nginx 主进程以 root 运行，还需要能免密
          <code className="mx-1">sudo nginx</code>——探测时会检查这一点并告诉你结果。
        </div>

        {m.error && <ErrorNote error={m.error} />}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button type="submit" disabled={m.isPending}>{m.isPending ? "保存中…" : "保存"}</Button>
        </div>
      </form>
    </Dialog>
  );
}
