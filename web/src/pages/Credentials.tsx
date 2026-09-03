import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { KeyRound, RefreshCcwDot, RefreshCw, ShieldCheck, Trash2 } from "lucide-react";
import { api, type Credential } from "@/lib/api";
import { formatTime } from "@/lib/format";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Textarea } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

const CAPS = [
  { id: "dns", label: "DNS-01 验证", hint: "签发证书必需，同时用于自动识别可管理的域名" },
  { id: "cdn", label: "CDN 部署", hint: "上传证书到 CAS 并绑定到 CDN 域名" },
  { id: "slb", label: "负载均衡", hint: "绑定证书到 SLB/ALB 监听" },
  { id: "oss", label: "OSS", hint: "OSS 自定义域名证书" },
];

export function Credentials() {
  const qc = useQueryClient();
  const [manualOpen, setManualOpen] = useState(false);
  const [autoOpen, setAutoOpen] = useState(false);
  const [rotating, setRotating] = useState<Credential>();

  const q = useQuery({ queryKey: ["credentials"], queryFn: () => api.get<Credential[]>("/credentials") });
  const refresh = () => qc.invalidateQueries({ queryKey: ["credentials"] });

  const sync = useMutation({
    mutationFn: (id: number) => api.post(`/credentials/${id}/sync`),
    onSuccess: refresh,
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/credentials/${id}`),
    onSuccess: refresh,
  });

  return (
    <>
      <PageHeader
        title="凭据"
        description="云账号密钥加密存放，主密钥不在数据库里——拿到数据库备份也解不开。"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => setManualOpen(true)}>
              <KeyRound className="size-3.5" />
              手动录入
            </Button>
            <Button size="sm" onClick={() => setAutoOpen(true)}>
              <ShieldCheck className="size-3.5" />
              自动创建子账号
            </Button>
          </>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>已保存的凭据</CardTitle>
          <CardDescription>
            录入后会立刻扫描该账号可管理的域名，之后新增证书时无需再选账号。
          </CardDescription>
        </CardHeader>
        <CardContent className="px-0 pt-1">
          {q.isLoading ? (
            <Loading />
          ) : q.error ? (
            <div className="px-5 pb-4">
              <ErrorNote error={q.error} onRetry={() => q.refetch()} />
            </div>
          ) : q.data!.length === 0 ? (
            <Empty
              title="还没有凭据"
              hint="推荐用「自动创建子账号」：提供一次管理凭据，系统会建好最小权限的 RAM 子账号，管理凭据不会被保存。"
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>名称</TH>
                  <TH>来源</TH>
                  <TH className="text-right">可管理域名</TH>
                  <TH className="w-full">健康状态</TH>
                  <TH className="w-px" />
                </TR>
              </THead>
              <TBody>
                {q.data!.map((c) => (
                  <TR key={c.id}>
                    <TD className="whitespace-nowrap">
                      <div className="font-medium">{c.name}</div>
                      {c.ram_user_name && (
                        <div className="text-muted-foreground text-xs">RAM 用户 {c.ram_user_name}</div>
                      )}
                    </TD>
                    <TD className="text-xs whitespace-nowrap">
                      {c.origin === "auto" ? "CertPilot 创建" : "手动录入"}
                    </TD>
                    <TD className="tabular text-right">{c.zone_count}</TD>
                    <TD>
                      {c.last_check_ok == null ? (
                        <StatusBadge state="busy">未检查</StatusBadge>
                      ) : c.last_check_ok ? (
                        <StatusBadge state="ok">正常</StatusBadge>
                      ) : (
                        <div className="flex flex-col items-start gap-1">
                          <StatusBadge state="danger">失效</StatusBadge>
                          <span
                            className="text-muted-foreground line-clamp-3 max-w-xs text-xs"
                            title={c.last_check_err}
                          >
                            {c.last_check_err}
                          </span>
                        </div>
                      )}
                      <div className="text-muted-foreground mt-0.5 text-xs">
                        {formatTime(c.last_checked_at)}
                      </div>
                    </TD>
                    <TD>
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="sm"
                          title="重新扫描可管理域名"
                          disabled={sync.isPending}
                          onClick={() => sync.mutate(c.id)}
                        >
                          <RefreshCw className="size-3.5" />
                        </Button>
                        {c.origin === "auto" && (
                          <Button
                            variant="ghost"
                            size="sm"
                            title="轮换 AccessKey"
                            onClick={() => setRotating(c)}
                          >
                            <RefreshCcwDot className="size-3.5" />
                          </Button>
                        )}
                        <Button
                          variant="ghost"
                          size="sm"
                          title="删除"
                          onClick={() => {
                            if (confirm(`删除凭据「${c.name}」？使用它的证书将无法续期。`))
                              remove.mutate(c.id);
                          }}
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

      <ManualDialog open={manualOpen} onClose={() => setManualOpen(false)} onDone={refresh} />
      <ProvisionDialog open={autoOpen} onClose={() => setAutoOpen(false)} onDone={refresh} />
      <RotateDialog
        credential={rotating}
        onClose={() => setRotating(undefined)}
        onDone={refresh}
      />
    </>
  );
}

function ManualDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({ name: "", access_key_id: "", access_key_secret: "", region: "cn-hangzhou" });
  const [note, setNote] = useState<string>();

  const m = useMutation({
    mutationFn: () => api.post<{ zones_synced: number; scan_error?: string }>("/credentials", form),
    onSuccess: (res) => {
      onDone();
      if (res.scan_error) {
        setNote(res.scan_error);
      } else {
        setNote(undefined);
        onClose();
      }
    },
  });

  return (
    <Dialog open={open} onClose={onClose} title="手动录入凭据" description="已有 RAM 子账号时使用。">
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          m.mutate();
        }}
      >
        <Field label="名称">
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="阿里云-生产" required />
        </Field>
        <Field label="AccessKey ID">
          <Input value={form.access_key_id} onChange={(e) => setForm({ ...form, access_key_id: e.target.value })} required />
        </Field>
        <Field label="AccessKey Secret" hint="加密后存储，保存后无法再读取。">
          <Input type="password" value={form.access_key_secret} onChange={(e) => setForm({ ...form, access_key_secret: e.target.value })} required />
        </Field>
        <Field label="地域" hint="影响 CAS 证书服务；DNS 是全局服务，不受影响。">
          <Input value={form.region} onChange={(e) => setForm({ ...form, region: e.target.value })} />
        </Field>

        {m.error && <ErrorNote error={m.error} />}
        {note && (
          <div className="bg-warn-soft text-warn rounded-md border border-warn/30 p-3 text-xs">{note}</div>
        )}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button type="submit" disabled={m.isPending}>{m.isPending ? "保存中…" : "保存并扫描域名"}</Button>
        </div>
      </form>
    </Dialog>
  );
}

/**
 * 自动创建走三步：选能力 → 预览策略 → 执行。
 * 预览这一步不能省——一个索要管理凭据的功能，透明度就是它的信任基础。
 */
function ProvisionDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [form, setForm] = useState({
    name: "",
    admin_access_key_id: "",
    admin_access_key_secret: "",
    region: "cn-hangzhou",
  });
  const [caps, setCaps] = useState<string[]>(["dns", "cdn"]);
  const [policy, setPolicy] = useState<string>();

  const preview = useMutation({
    mutationFn: () => api.post<{ policy: string }>("/credentials/policy-preview", { capabilities: caps }),
    onSuccess: (r) => setPolicy(r.policy),
  });
  const provision = useMutation({
    mutationFn: () => api.post<{ ram_user: string }>("/credentials/provision", { ...form, capabilities: caps }),
    onSuccess: () => {
      onDone();
      onClose();
    },
  });

  const toggle = (id: string) =>
    setCaps((prev) => (prev.includes(id) ? prev.filter((c) => c !== id) : [...prev, id]));

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="自动创建 RAM 子账号"
      description="管理凭据只用于本次创建，不会被保存。"
      className="max-w-2xl"
    >
      <form
        className="flex flex-col gap-4"
        onSubmit={(e) => {
          e.preventDefault();
          provision.mutate();
        }}
      >
        <div className="bg-warn-soft text-warn rounded-md border border-warn/30 p-3 text-xs">
          建议不要使用主账号 AccessKey。先在控制台建一个带 <code>AliyunRAMFullAccess</code> 的临时子账号，
          用它跑完这个向导后删掉——即使有闪失，泄露的也不是主账号凭据。
        </div>

        <Field label="新凭据名称">
          <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="阿里云-生产" required />
        </Field>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="管理 AccessKey ID">
            <Input value={form.admin_access_key_id} onChange={(e) => setForm({ ...form, admin_access_key_id: e.target.value })} required />
          </Field>
          <Field label="管理 AccessKey Secret">
            <Input type="password" value={form.admin_access_key_secret} onChange={(e) => setForm({ ...form, admin_access_key_secret: e.target.value })} required />
          </Field>
        </div>

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">需要的能力</span>
          <div className="grid gap-2 sm:grid-cols-2">
            {CAPS.map((c) => (
              <label key={c.id} className="hover:bg-accent/50 flex items-start gap-2 rounded-md border p-2.5">
                <Checkbox checked={caps.includes(c.id)} onChange={() => { toggle(c.id); setPolicy(undefined); }} className="mt-0.5" />
                <span className="flex flex-col">
                  <span className="text-sm">{c.label}</span>
                  <span className="text-muted-foreground text-xs">{c.hint}</span>
                </span>
              </label>
            ))}
          </div>
        </div>

        <div className="flex flex-col gap-2">
          <div className="flex items-center justify-between">
            <span className="text-sm font-medium">权限策略</span>
            <Button type="button" variant="outline" size="sm" disabled={caps.length === 0 || preview.isPending} onClick={() => preview.mutate()}>
              {preview.isPending ? "生成中…" : "预览将要授予的权限"}
            </Button>
          </div>
          {policy && <Textarea readOnly rows={12} value={policy} className="text-xs" />}
          {preview.error && <ErrorNote error={preview.error} />}
        </div>

        {provision.error && <ErrorNote error={provision.error} />}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button type="submit" disabled={provision.isPending || caps.length === 0}>
            {provision.isPending ? "创建中…" : "创建子账号"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}

/**
 * AK 轮换。顺序是「建新 → 验证 → 入库 → 删旧」，
 * 任何一步失败都停在安全状态：旧 AccessKey 始终可用，
 * 直到新的被确认能工作。
 */
function RotateDialog({
  credential, onClose, onDone,
}: {
  credential?: Credential;
  onClose: () => void;
  onDone: () => void;
}) {
  const [form, setForm] = useState({ admin_access_key_id: "", admin_access_key_secret: "" });
  const [warning, setWarning] = useState<string>();

  const m = useMutation({
    mutationFn: () => api.post<{ warning?: string }>(`/credentials/${credential!.id}/rotate`, form),
    onSuccess: (r) => {
      onDone();
      if (r.warning) {
        setWarning(r.warning);
      } else {
        onClose();
      }
    },
  });

  return (
    <Dialog
      open={!!credential}
      onClose={onClose}
      title={`轮换「${credential?.name ?? ""}」的 AccessKey`}
      description="管理凭据只用于本次轮换，不会被保存。"
      className="max-w-xl"
    >
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <div className="bg-muted text-muted-foreground rounded-md p-3 text-xs">
          轮换需要管理凭据：子账号自己没有创建 AccessKey 的权限——这正是最小权限的应有之义。
          RAM 用户最多持有两把 AccessKey，因此可以先建新的、确认能用，再删掉旧的，全程不中断。
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="管理 AccessKey ID">
            <Input
              value={form.admin_access_key_id}
              onChange={(e) => setForm({ ...form, admin_access_key_id: e.target.value })}
              required
            />
          </Field>
          <Field label="管理 AccessKey Secret">
            <Input
              type="password"
              value={form.admin_access_key_secret}
              onChange={(e) => setForm({ ...form, admin_access_key_secret: e.target.value })}
              required
            />
          </Field>
        </div>

        {m.error && <ErrorNote error={m.error} />}
        {warning && (
          <div className="bg-warn-soft text-warn rounded-md border border-warn/30 p-3 text-xs">
            {warning}
          </div>
        )}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>
            {warning ? "关闭" : "取消"}
          </Button>
          {!warning && (
            <Button type="submit" disabled={m.isPending}>
              {m.isPending ? "轮换中…" : "开始轮换"}
            </Button>
          )}
        </div>
      </form>
    </Dialog>
  );
}
