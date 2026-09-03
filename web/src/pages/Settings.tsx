import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus } from "lucide-react";
import { api, type ACMEAccount } from "@/lib/api";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { StatusBadge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

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

      <CreateDialog open={open} onClose={() => setOpen(false)} onDone={() => qc.invalidateQueries({ queryKey: ["acme-accounts"] })} />
    </>
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
