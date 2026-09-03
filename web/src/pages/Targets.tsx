import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Trash2 } from "lucide-react";
import { api, type Credential, type DeployTarget, type ServerService } from "@/lib/api";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/field";
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
  const [serviceID, setServiceID] = useState<number>(0);
  const [certPath, setCertPath] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [hookURL, setHookURL] = useState("");
  const [includeKey, setIncludeKey] = useState(true);
  const [k8s, setK8s] = useState({ namespace: "default", secret_name: "" });

  const isSSH = kind === "ssh_nginx";
  const isWebhook = kind === "webhook";
  const isK8s = kind === "k8s_secret";
  const isCDN = kind === "aliyun_cdn";

  const creds = useQuery({
    queryKey: ["credentials"],
    queryFn: () => api.get<Credential[]>("/credentials"),
    enabled: open && (isCDN || isK8s),
  });
  const services = useQuery({
    queryKey: ["services"],
    queryFn: () => api.get<ServerService[]>("/services"),
    enabled: open && isSSH,
  });

  // 选中服务后，用它发现的证书路径预填——多数情况下直接沿用即可。
  const pickService = (id: number) => {
    setServiceID(id);
    const svc = services.data?.find((s) => s.id === id);
    const first = svc?.discovered_certs?.[0];
    if (first) {
      setCertPath(first.CertPath);
      setKeyPath(first.KeyPath);
    }
  };

  const m = useMutation({
    mutationFn: () => {
      const domains = domainText.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);
      const base = { name, kind, credential_id: null as number | null, server_service_id: null as number | null };

      if (isSSH) {
        return api.post("/targets", {
          ...base,
          server_service_id: serviceID,
          params: { cert_path: certPath, key_path: keyPath, verify_domains: domains },
        });
      }
      if (isWebhook) {
        return api.post("/targets", {
          ...base,
          params: { url: hookURL, include_key: includeKey, verify_domains: domains },
        });
      }
      if (isK8s) {
        return api.post("/targets", {
          ...base,
          credential_id: credentialID || creds.data?.[0]?.id,
          params: { ...k8s, verify_domains: domains },
        });
      }
      return api.post("/targets", {
        ...base,
        credential_id: credentialID || creds.data?.[0]?.id,
        params: { domains },
      });
    },
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
            <option value="ssh_nginx">Nginx（经 SSH）</option>
            <option value="k8s_secret">Kubernetes Secret</option>
            <option value="webhook">通用 Webhook</option>
          </Select>
        </Field>

        {isSSH ? (
          <>
            <Field label="目标服务" hint="先在「服务器」里探测一次，这里才会出现可选项。">
              <Select value={serviceID} onChange={(e) => pickService(Number(e.target.value))}>
                <option value={0}>请选择</option>
                {services.data?.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.host_name} · {s.compose_service ?? s.container_name ?? s.kind}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="证书路径" hint="容器形态填容器内路径，系统会自动映射到宿主机。">
              <Input value={certPath} onChange={(e) => setCertPath(e.target.value)} placeholder="/etc/nginx/certs/example.com/fullchain.pem" required />
            </Field>
            <Field label="私钥路径">
              <Input value={keyPath} onChange={(e) => setKeyPath(e.target.value)} placeholder="/etc/nginx/certs/example.com/privkey.pem" required />
            </Field>
            <Field label="拨测域名" hint="部署后用它确认线上真的换了新证书。留空则跳过校验。">
              <Textarea rows={3} value={domainText} onChange={(e) => setDomainText(e.target.value)} placeholder={"example.com"} />
            </Field>
          </>
        ) : isWebhook ? (
          <>
            <Field
              label="接收端点"
              hint="证书会以 JSON POST 到这里。没有内置支持的场景写个脚本接住就行。"
            >
              <Input value={hookURL} onChange={(e) => setHookURL(e.target.value)}
                placeholder="https://internal.example.com/hooks/cert" required />
            </Field>
            <label className="hover:bg-accent/50 flex items-start gap-2 rounded-md border p-2.5">
              <Checkbox checked={includeKey} onChange={() => setIncludeKey((v) => !v)} className="mt-0.5" />
              <span className="flex flex-col">
                <span className="text-sm">同时发送私钥</span>
                <span className="text-muted-foreground text-xs">
                  关掉的话对端多半用不了；打开则意味着私钥会离开本系统，请只指向可信端点并使用 HTTPS。
                </span>
              </span>
            </label>
            <Field label="拨测域名" hint="部署后用它确认线上真的换了新证书。留空则跳过校验。">
              <Textarea rows={3} value={domainText} onChange={(e) => setDomainText(e.target.value)} />
            </Field>
          </>
        ) : isK8s ? (
          <>
            <Field label="使用凭据" hint="需要一份含 API Server 地址与 ServiceAccount 令牌的凭据。">
              <Select value={credentialID} onChange={(e) => setCredentialID(Number(e.target.value))}>
                {creds.data?.length ? (
                  creds.data.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)
                ) : (
                  <option value={0}>请先添加凭据</option>
                )}
              </Select>
            </Field>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="命名空间">
                <Input value={k8s.namespace} onChange={(e) => setK8s({ ...k8s, namespace: e.target.value })} required />
              </Field>
              <Field label="Secret 名称" hint="类型固定为 kubernetes.io/tls。">
                <Input value={k8s.secret_name} onChange={(e) => setK8s({ ...k8s, secret_name: e.target.value })}
                  placeholder="example-com-tls" required />
              </Field>
            </div>
            <Field label="拨测域名" hint="用它确认 Ingress 真的加载了新证书。">
              <Textarea rows={3} value={domainText} onChange={(e) => setDomainText(e.target.value)} />
            </Field>
          </>
        ) : (
          <>
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
          </>
        )}

        {m.error && <ErrorNote error={m.error} />}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button
            type="submit"
            disabled={
              m.isPending ||
              (isSSH && !serviceID) ||
              ((isCDN || isK8s) && !creds.data?.length)
            }
          >
            {m.isPending ? "保存中…" : "保存"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
