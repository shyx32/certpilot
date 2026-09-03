import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Plus, Send, Trash2 } from "lucide-react";
import { api, type NotifyChannelsResponse } from "@/lib/api";
import { PageHeader } from "@/components/layout/page";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Checkbox, Field, Input, Select } from "@/components/ui/field";
import { Dialog } from "@/components/ui/dialog";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";

const kindLabels: Record<string, string> = {
  dingtalk: "钉钉群机器人",
  wecom: "企业微信群机器人",
  feishu: "飞书群机器人",
  webhook: "通用 Webhook",
};

export function Notifications() {
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [tested, setTested] = useState<Record<number, string>>({});

  const q = useQuery({
    queryKey: ["notify-channels"],
    queryFn: () => api.get<NotifyChannelsResponse>("/notify-channels"),
  });
  const refresh = () => qc.invalidateQueries({ queryKey: ["notify-channels"] });

  const test = useMutation({
    mutationFn: (id: number) => api.post(`/notify-channels/${id}/test`),
    onSuccess: (_, id) => setTested((p) => ({ ...p, [id]: "ok" })),
    onError: (e, id) => setTested((p) => ({ ...p, [id]: (e as Error).message })),
  });
  const remove = useMutation({
    mutationFn: (id: number) => api.del(`/notify-channels/${id}`),
    onSuccess: refresh,
  });

  const eventLabel = (v: string) =>
    q.data?.events.find((e) => e.value === v)?.label ?? v;

  return (
    <>
      <PageHeader
        title="通知渠道"
        description="巡检发现的问题会汇总成一条消息发出去——20 个域名同时告警不该刷屏。"
        actions={
          <Button size="sm" onClick={() => setOpen(true)}>
            <Plus className="size-3.5" />
            添加渠道
          </Button>
        }
      />

      <Card>
        <CardContent className="px-0 py-1">
          {q.isLoading ? (
            <Loading />
          ) : q.error ? (
            <div className="p-5"><ErrorNote error={q.error} onRetry={() => q.refetch()} /></div>
          ) : !q.data!.channels.length ? (
            <Empty
              title="还没有通知渠道"
              hint="不加也能用，但证书出问题时只能靠自己去看界面。加一个群机器人，异常会主动找上门。"
              action={<Button size="sm" onClick={() => setOpen(true)}>添加渠道</Button>}
            />
          ) : (
            <Table>
              <THead>
                <TR>
                  <TH>名称</TH>
                  <TH>类型</TH>
                  <TH className="w-full">订阅事件</TH>
                  <TH>测试</TH>
                  <TH className="w-px" />
                </TR>
              </THead>
              <TBody>
                {q.data!.channels.map((c) => (
                  <TR key={c.id}>
                    <TD className="font-medium whitespace-nowrap">{c.name}</TD>
                    <TD className="text-xs whitespace-nowrap">{kindLabels[c.kind] ?? c.kind}</TD>
                    <TD className="text-muted-foreground text-xs">
                      {c.events?.length ? c.events.map(eventLabel).join("、") : "全部事件"}
                    </TD>
                    <TD>
                      {tested[c.id] === "ok" ? (
                        <StatusBadge state="ok">已发送</StatusBadge>
                      ) : tested[c.id] ? (
                        <div className="flex flex-col items-start gap-1">
                          <StatusBadge state="danger">失败</StatusBadge>
                          <span className="text-muted-foreground line-clamp-2 text-xs">
                            {tested[c.id]}
                          </span>
                        </div>
                      ) : (
                        <Button variant="outline" size="sm" disabled={test.isPending}
                          onClick={() => test.mutate(c.id)}>
                          <Send className="size-3.5" />
                          发一条
                        </Button>
                      )}
                    </TD>
                    <TD>
                      <Button variant="ghost" size="sm"
                        onClick={() => confirm(`删除渠道「${c.name}」？`) && remove.mutate(c.id)}>
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

      <AddDialog
        open={open}
        onClose={() => setOpen(false)}
        onDone={refresh}
        kinds={q.data?.kinds ?? []}
        events={q.data?.events ?? []}
      />
    </>
  );
}

function AddDialog({
  open, onClose, onDone, kinds, events,
}: {
  open: boolean;
  onClose: () => void;
  onDone: () => void;
  kinds: string[];
  events: { value: string; label: string }[];
}) {
  const [form, setForm] = useState({ name: "", kind: "dingtalk", url: "", keyword: "" });
  const [selected, setSelected] = useState<string[]>([]);

  const m = useMutation({
    mutationFn: () => api.post("/notify-channels", { ...form, events: selected }),
    onSuccess: () => { onDone(); onClose(); },
  });

  const toggle = (v: string) =>
    setSelected((p) => (p.includes(v) ? p.filter((x) => x !== v) : [...p, v]));

  return (
    <Dialog
      open={open}
      onClose={onClose}
      title="添加通知渠道"
      description="保存后可以先发一条测试消息，确认群里真的收得到。"
      className="max-w-xl"
    >
      <form className="flex flex-col gap-4" onSubmit={(e) => { e.preventDefault(); m.mutate(); }}>
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="名称">
            <Input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })}
              placeholder="运维群" required />
          </Field>
          <Field label="类型">
            <Select value={form.kind} onChange={(e) => setForm({ ...form, kind: e.target.value })}>
              {kinds.map((k) => <option key={k} value={k}>{kindLabels[k] ?? k}</option>)}
            </Select>
          </Field>
        </div>

        <Field label="Webhook 地址" hint="群机器人的推送地址，加密存放。">
          <Input value={form.url} onChange={(e) => setForm({ ...form, url: e.target.value })}
            placeholder="https://oapi.dingtalk.com/robot/send?access_token=…" required />
        </Field>

        {form.kind === "dingtalk" && (
          <Field
            label="安全关键词"
            hint="钉钉机器人若设置了「自定义关键词」，消息里必须包含它，否则会被静默丢弃。"
          >
            <Input value={form.keyword} onChange={(e) => setForm({ ...form, keyword: e.target.value })}
              placeholder="CertPilot" />
          </Field>
        )}

        <div className="flex flex-col gap-2">
          <span className="text-sm font-medium">订阅事件</span>
          <p className="text-muted-foreground text-xs">不勾选表示接收全部事件。</p>
          <div className="grid gap-2 sm:grid-cols-2">
            {events.map((e) => (
              <label key={e.value} className="hover:bg-accent/50 flex items-center gap-2 rounded-md border p-2 text-sm">
                <Checkbox checked={selected.includes(e.value)} onChange={() => toggle(e.value)} />
                {e.label}
              </label>
            ))}
          </div>
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
