import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Plus, Trash2 } from "lucide-react";
import { api, type ACMEAccount, type ShareLink } from "@/lib/api";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";
import { formatDate } from "@/lib/format";

const DIRECTORIES = [
  { url: "https://acme-staging-v02.api.letsencrypt.org/directory", label: "Let's Encrypt（staging，用于试跑）", staging: true },
  { url: "https://acme-v02.api.letsencrypt.org/directory", label: "Let's Encrypt（生产）", staging: false },
];

export function Settings() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ["acme-accounts"], queryFn: () => api.get<ACMEAccount[]>("/acme-accounts") });

  return (
    <>
      <PageHeader
        title="CA 账号"
        description="账号私钥注册后无法再取回，因此和证书私钥一样加密保存。"
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus className="size-3.5" />
            添加账号
          </Button>
        }
      />

      <Card>
        <CardHeader>
          <CardTitle>已配置的 CA</CardTitle>
          <CardDescription>
            首次接入建议先用 staging 跑通全流程，确认无误再切生产——生产环境的签发配额有限。
          </CardDescription>
        </CardHeader>
        <CardContent className="px-0 pt-1">
          {q.isLoading ? (
            <Loading />
          ) : q.error ? (
            <div className="px-5 pb-4"><ErrorNote error={q.error} onRetry={() => q.refetch()} /></div>
          ) : q.data!.length === 0 ? (
            <Empty title="还没有 CA 账号" hint="签发证书前需要先注册一个 ACME 账号，只需邮箱。" action={<Button size="sm" onClick={() => setOpen(true)}>添加账号</Button>} />
          ) : (
            <Table>
              <THead>
                <TR><TH>名称</TH><TH>邮箱</TH><TH>环境</TH><TH className="w-full">目录地址</TH></TR>
              </THead>
              <TBody>
                {q.data!.map((a) => (
                  <TR key={a.id}>
                    <TD className="font-medium whitespace-nowrap">{a.name}</TD>
                    <TD className="text-xs whitespace-nowrap">{a.email}</TD>
                    <TD>
                      <StatusBadge state={a.is_staging ? "warn" : "ok"}>
                        {a.is_staging ? "staging" : "生产"}
                      </StatusBadge>
                    </TD>
                    <TD className="text-muted-foreground text-xs">
                      <span className="line-clamp-1">{a.directory_url}</span>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <ShareLinks />

      <CreateDialog open={open} onClose={() => setOpen(false)} onDone={() => qc.invalidateQueries({ queryKey: ["acme-accounts"] })} />
    </>
  );
}

/**
 * 只读分享看板：给不需要登录后台的人看一眼「证书还好吗」。
 * 页面只暴露域名与状态，不含证书路径、颁发者或任务日志。
 */
function ShareLinks() {
  const qc = useQueryClient();
  const [name, setName] = useState("");
  const [copied, setCopied] = useState<number>();

  const q = useQuery({ queryKey: ["share-links"], queryFn: () => api.get<ShareLink[]>("/share-links") });
  const refresh = () => qc.invalidateQueries({ queryKey: ["share-links"] });

  const create = useMutation({
    mutationFn: () => api.post("/share-links", { name: name || "证书状态", ttl_days: 30 }),
    onSuccess: () => { setName(""); refresh(); },
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/share-links/${id}`),
    onSuccess: refresh,
  });

  const urlOf = (t: string) => `${location.origin}/status/${t}`;

  return (
    <Card className="mt-4">
      <CardHeader>
        <CardTitle>只读分享链接</CardTitle>
        <CardDescription>
          持有链接的人无需登录即可看到域名与到期状态；证书路径、凭据与任务日志不会出现在那个页面上。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3 pt-1">
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(e) => { e.preventDefault(); create.mutate(); }}
        >
          <div className="min-w-48 flex-1">
            <Field label="用途">
              <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="给业务方看的状态页" />
            </Field>
          </div>
          <Button type="submit" size="sm" disabled={create.isPending}>
            <Plus className="size-3.5" />
            {create.isPending ? "创建中…" : "创建链接"}
          </Button>
        </form>

        {create.error && <ErrorNote error={create.error} />}

        {q.isLoading ? (
          <Loading />
        ) : !q.data?.length ? (
          <p className="text-muted-foreground py-2 text-xs">还没有分享链接。</p>
        ) : (
          <div className="space-y-1.5">
            {q.data.map((l) => (
              <div key={l.id} className="flex flex-wrap items-center gap-2 rounded-md border p-2.5">
                <span className="text-sm font-medium">{l.name}</span>
                <code className="bg-muted min-w-0 flex-1 truncate rounded px-2 py-1 font-mono text-xs">
                  {urlOf(l.token)}
                </code>
                {l.expires_at && (
                  <span className="text-muted-foreground text-xs">
                    到期 {formatDate(l.expires_at)}
                  </span>
                )}
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => {
                    navigator.clipboard?.writeText(urlOf(l.token));
                    setCopied(l.id);
                    setTimeout(() => setCopied(undefined), 2000);
                  }}
                >
                  <Copy className="size-3.5" />
                  {copied === l.id ? "已复制" : "复制"}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => confirm(`删除链接「${l.name}」？持有它的人将无法再访问。`) && remove.mutate(l.id)}
                >
                  <Trash2 className="text-danger size-3.5" />
                </Button>
              </div>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function CreateDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [email, setEmail] = useState("");
  const [dirIdx, setDirIdx] = useState(0);

  const m = useMutation({
    mutationFn: () =>
      api.post("/acme-accounts", {
        email,
        directory_url: DIRECTORIES[dirIdx].url,
        is_staging: DIRECTORIES[dirIdx].staging,
      }),
    onSuccess: () => { onDone(); onClose(); },
  });

  return (
    <Dialog open={open} onClose={onClose} title="添加 CA 账号" description="账号会在第一次签发时自动向 CA 注册。">
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <Field label="邮箱" hint="CA 用它发送证书到期提醒，请填写真实可收信的地址。">
          <Input type="email" value={email} onChange={(e) => setEmail(e.target.value)} required />
        </Field>
        <Field label="环境">
          <Select value={dirIdx} onChange={(e) => setDirIdx(Number(e.target.value))}>
            {DIRECTORIES.map((d, i) => <option key={d.url} value={i}>{d.label}</option>)}
          </Select>
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
