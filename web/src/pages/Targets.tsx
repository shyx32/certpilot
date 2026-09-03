import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api, type Credential, type DeployTarget } from "@/lib/api";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Textarea } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

export function Targets() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ["targets"], queryFn: () => api.get<DeployTarget[]>("/targets") });
  const refresh = () => qc.invalidateQueries({ queryKey: ["targets"] });

  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/targets/${id}`),
    onSuccess: refresh,
  });

  return (
    <>
      <PageHeader
        title="部署目标"
        description="证书签发后自动推送到这些地方，并拨测确认线上确实换了新证书。"
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus className="size-3.5" />
            添加目标
          </Button>
        }
      />

      <Card>
        <CardContent className="px-0 py-1">
          {q.isLoading ? (
            <Loading />
          ) : q.error ? (
            <div className="p-5"><ErrorNote error={q.error} onRetry={() => q.refetch()} /></div>
          ) : q.data!.length === 0 ? (
            <Empty
              title="还没有部署目标"
              hint="不加也可以——证书会正常签发并保存在库中，只是不会自动推送到任何地方。"
              action={<Button size="sm" onClick={() => setOpen(true)}>添加目标</Button>}
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>名称</TH>
                  <TH>类型</TH>
                  <TH className="w-full">配置</TH>
                  <TH className="w-px" />
                </TR>
              </THead>
              <TBody>
                {q.data!.map((t) => (
                  <TR key={t.id}>
                    <TD className="font-medium whitespace-nowrap">{t.name}</TD>
                    <TD className="text-xs whitespace-nowrap">{t.kind}</TD>
                    <TD className="text-muted-foreground font-mono text-xs">
                      <span className="line-clamp-1" title={JSON.stringify(t.params)}>
                        {JSON.stringify(t.params)}
                      </span>
                    </TD>
                    <TD>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => confirm(`删除目标「${t.name}」？`) && remove.mutate(t.id)}
                      >
                        <Trash2 className="text-danger size-3.5" />
                      </Button>
                    </TD>
                  </TR>
                ))}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateDialog open={open} onClose={() => setOpen(false)} onDone={refresh} />
    </>
  );
}

function CreateDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [kind, setKind] = useState("aliyun_cdn");
  const [credentialID, setCredentialID] = useState<number>(0);
  const [domainText, setDomainText] = useState("");

  const creds = useQuery({
    queryKey: ["credentials"],
    queryFn: () => api.get<Credential[]>("/credentials"),
    enabled: open,
  });

  const m = useMutation({
    mutationFn: () =>
      api.post("/targets", {
        name,
        kind,
        credential_id: credentialID || creds.data?.[0]?.id,
        params: { domains: domainText.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean) },
      }),
    onSuccess: () => { onDone(); onClose(); },
  });

  return (
    <Dialog open={open} onClose={onClose} title="添加部署目标" description="证书签发后会自动推送到这里。">
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <Field label="名称">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="生产 CDN" required />
        </Field>
        <Field label="类型">
          <Select value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="aliyun_cdn">阿里云 CDN</option>
          </Select>
        </Field>
        <Field label="使用凭据">
          <Select value={credentialID} onChange={(e) => setCredentialID(Number(e.target.value))}>
            {creds.data?.length ? (
              creds.data.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)
            ) : (
              <option value={0}>请先添加凭据</option>
            )}
          </Select>
        </Field>
        <Field label="CDN 加速域名" hint="每行一个。一张证书可以同时绑定多个域名，单个失败不影响其余。">
          <Textarea rows={4} value={domainText} onChange={(e) => setDomainText(e.target.value)} placeholder={"cdn.example.com\nimg.example.com"} required />
        </Field>

        {m.error && <ErrorNote error={m.error} />}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button type="submit" disabled={m.isPending || !creds.data?.length}>
            {m.isPending ? "保存中…" : "保存"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
