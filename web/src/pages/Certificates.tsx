import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { Plus } from "lucide-react";
import { api, type ACMEAccount, type CertConfig, type DeployTarget, type DomainResolution } from "@/lib/api";
import { certStatus, formatDate } from "@/lib/format";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Select, Textarea } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

export function Certificates() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const q = useQuery({ queryKey: ["certs"], queryFn: () => api.get<CertConfig[]>("/certificates") });

  return (
    <>
      <PageHeader
        title="证书列表"
        description="到期前 30 天自动续期，无需人工介入。"
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus className="size-3.5" />
            申请证书
          </Button>
        }
      />

      <Card>
        <CardContent className="px-0 py-1">
          {q.isLoading ? (
            <Loading />
          ) : q.error ? (
            <div className="p-5">
              <ErrorNote error={q.error} onRetry={() => q.refetch()} />
            </div>
          ) : q.data!.length === 0 ? (
            <Empty
              title="还没有证书"
              hint="先在「凭据」里添加一个云账号，然后回到这里输入域名——系统会自动判断该用哪个账号验证。"
              action={<Button size="sm" onClick={() => setOpen(true)}>申请证书</Button>}
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>名称</TH>
                  <TH className="w-full">域名</TH>
                  <TH>验证</TH>
                  <TH>到期</TH>
                  <TH className="text-right">剩余</TH>
                  <TH>状态</TH>
                </TR>
              </THead>
              <TBody>
                {q.data!.map((c) => {
                  const s = certStatus(c);
                  return (
                    <TR key={c.id}>
                      <TD className="font-medium whitespace-nowrap">
                        <Link to={`/certificates/${c.id}`} className="hover:underline">{c.name}</Link>
                      </TD>
                      <TD className="text-muted-foreground text-xs">
                        <span className="line-clamp-1" title={c.domains.join(", ")}>{c.domains.join(", ")}</span>
                      </TD>
                      <TD className="text-xs whitespace-nowrap">{c.challenge_type}</TD>
                      <TD className="text-xs whitespace-nowrap">{formatDate(c.not_after)}</TD>
                      <TD className="tabular text-right whitespace-nowrap">
                        {c.days_left == null ? "—" : `${c.days_left} 天`}
                      </TD>
                      <TD><StatusBadge state={s.state}>{s.text}</StatusBadge></TD>
                    </TR>
                  );
                })}
              </TBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <CreateDialog
        open={open}
        onClose={() => setOpen(false)}
        onDone={() => qc.invalidateQueries({ queryKey: ["certs"] })}
      />
    </>
  );
}

function CreateDialog({ open, onClose, onDone }: { open: boolean; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState("");
  const [domainText, setDomainText] = useState("");
  const [keyType, setKeyType] = useState("EC256");
  const [accountID, setAccountID] = useState<number>(0);
  const [targetIDs, setTargetIDs] = useState<number[]>([]);
  const [checks, setChecks] = useState<DomainResolution[]>();

  const accounts = useQuery({
    queryKey: ["acme-accounts"],
    queryFn: () => api.get<ACMEAccount[]>("/acme-accounts"),
    enabled: open,
  });
  const targets = useQuery({
    queryKey: ["targets"],
    queryFn: () => api.get<DeployTarget[]>("/targets"),
    enabled: open,
  });

  const domains = domainText.split(/[\s,]+/).map((d) => d.trim()).filter(Boolean);

  // 输入时就知道能不能签，而不是提交后看日志排查。
  const resolve = useMutation({
    mutationFn: () => api.post<DomainResolution[]>("/certificates/resolve", { domains }),
    onSuccess: setChecks,
  });
  const create = useMutation({
    mutationFn: () =>
      api.post("/certificates", {
        name,
        domains,
        key_type: keyType,
        acme_account_id: accountID || accounts.data?.[0]?.id,
        target_ids: targetIDs,
      }),
    onSuccess: () => {
      onDone();
      onClose();
    },
  });

  return (
    <Dialog open={open} onClose={onClose} title="申请证书" description="只需输入域名，系统会自动匹配可用的 DNS 账号。" className="max-w-2xl">
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); create.mutate(); }}>
        <Field label="名称">
          <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="example-wildcard" required />
        </Field>

        <Field label="域名" hint="每行一个，或用空格 / 逗号分隔。通配符如 *.example.com 只能用 DNS-01 验证。">
          <Textarea
            rows={4}
            value={domainText}
            onChange={(e) => { setDomainText(e.target.value); setChecks(undefined); }}
            placeholder={"*.example.com\nexample.com"}
            required
          />
        </Field>

        <div className="flex flex-col gap-2">
          <Button type="button" variant="outline" size="sm" disabled={domains.length === 0 || resolve.isPending} onClick={() => resolve.mutate()}>
            {resolve.isPending ? "检查中…" : "检查域名归属"}
          </Button>
          {checks && (
            <div className="space-y-1.5 rounded-md border p-3">
              {checks.map((c) => (
                <div key={c.domain} className="flex flex-wrap items-center gap-2 text-xs">
                  <StatusBadge state={c.ok ? "ok" : "danger"}>{c.ok ? "可签发" : "无法签发"}</StatusBadge>
                  <span className="font-medium">{c.domain}</span>
                  {c.ok ? (
                    <span className="text-muted-foreground">
                      → zone {c.zone}，记录 {c.record}，账号 {c.credential}
                    </span>
                  ) : (
                    <span className="text-danger">{c.reason}</span>
                  )}
                </div>
              ))}
            </div>
          )}
          {resolve.error && <ErrorNote error={resolve.error} />}
        </div>

        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="密钥算法" hint="EC256 更短更快；老客户端多时选 RSA2048。">
            <Select value={keyType} onChange={(e) => setKeyType(e.target.value)}>
              <option value="EC256">EC256</option>
              <option value="RSA2048">RSA2048</option>
              <option value="RSA4096">RSA4096</option>
            </Select>
          </Field>
          <Field label="CA 账号">
            <Select value={accountID} onChange={(e) => setAccountID(Number(e.target.value))}>
              {accounts.data?.length ? (
                accounts.data.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                    {a.is_staging ? "（staging）" : ""}
                  </option>
                ))
              ) : (
                <option value={0}>请先添加 CA 账号</option>
              )}
            </Select>
          </Field>
        </div>

        {!!targets.data?.length && (
          <div className="flex flex-col gap-2">
            <span className="text-sm font-medium">部署到</span>
            <div className="grid gap-2 sm:grid-cols-2">
              {targets.data.map((t) => (
                <label key={t.id} className="hover:bg-accent/50 flex items-center gap-2 rounded-md border p-2.5 text-sm">
                  <Checkbox
                    checked={targetIDs.includes(t.id)}
                    onChange={() =>
                      setTargetIDs((p) => (p.includes(t.id) ? p.filter((x) => x !== t.id) : [...p, t.id]))
                    }
                  />
                  <span>{t.name}</span>
                  <span className="text-muted-foreground text-xs">{t.kind}</span>
                </label>
              ))}
            </div>
          </div>
        )}

        {create.error && <ErrorNote error={create.error} />}

        <div className="flex justify-end gap-2">
          <Button type="button" variant="outline" onClick={onClose}>取消</Button>
          <Button type="submit" disabled={create.isPending || !accounts.data?.length}>
            {create.isPending ? "创建中…" : "创建"}
          </Button>
        </div>
      </form>
    </Dialog>
  );
}
