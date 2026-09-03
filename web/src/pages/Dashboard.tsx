import { useQuery } from "@tanstack/react-query";
import { Link } from "react-router-dom";
import { api, type Overview } from "@/lib/api";
import { certStatus, jobStatus, stageName } from "@/lib/format";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { PageHeader, Stat } from "@/components/layout/page";
import { StatusBadge } from "@/components/ui/badge";
import { Table, TBody, TD, TH, THead, TR } from "@/components/ui/table";
import { Empty, ErrorNote, Loading } from "@/components/ui/state";
import { Button } from "@/components/ui/button";

export function Dashboard() {
  const q = useQuery({ queryKey: ["overview"], queryFn: () => api.get<Overview>("/overview") });

  if (q.isLoading) return <Loading />;
  if (q.error) return <ErrorNote error={q.error} onRetry={() => q.refetch()} />;
  const d = q.data!;
  const issued = d.buckets.reduce((a, b) => a + b, 0);

  return (
    <>
      <PageHeader
        title="仪表盘"
        description="正常时这一页应该几乎全是绿的，异常会自己跳出来。"
      />

      <div className="mb-4 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Stat label="托管证书" value={d.cert_count} hint={`覆盖 ${d.domain_count} 个域名`} />
        <Stat
          label="30 天内到期"
          value={d.expiring_soon}
          hint={d.expiring_soon > 0 ? "已排入续期队列" : "暂无临期证书"}
          tone={d.expiring_soon > 0 ? "warn" : undefined}
        />
        <Stat
          label="过期或临界"
          value={d.expired}
          hint={d.expired > 0 ? "需要立即处理" : "全部在有效期内"}
          tone={d.expired > 0 ? "danger" : undefined}
        />
        <Stat
          label="失败任务"
          value={d.failed_jobs}
          hint="最近 10 条任务中"
          tone={d.failed_jobs > 0 ? "danger" : undefined}
        />
      </div>

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,2fr)_minmax(0,1fr)]">
        <Card>
          <CardHeader>
            <CardTitle>证书</CardTitle>
            <CardDescription>按剩余有效期排序，需要处理的排在最前。</CardDescription>
          </CardHeader>
          <CardContent className="px-0 pt-2 pb-2">
            {d.certs.length === 0 ? (
              <Empty
                title="还没有证书"
                hint="先添加一个云账号凭据，然后输入域名即可自动签发。"
                action={<Link to="/certificates"><Button size="sm">去添加</Button></Link>}
              />
            ) : (
              <Table>
                <THead>
                  <TR>
                    <TH>名称</TH>
                    {/* w-full 让域名列吸收剩余宽度，右侧列才不会被挤到边上 */}
                    <TH className="w-full">域名</TH>
                    <TH className="text-right">剩余</TH>
                    <TH>状态</TH>
                  </TR>
                </THead>
                <TBody>
                  {d.certs.map((c) => {
                    const s = certStatus(c);
                    return (
                      <TR key={c.id}>
                        <TD className="font-medium whitespace-nowrap">
                          <Link to={`/certificates/${c.id}`} className="hover:underline">
                            {c.name}
                          </Link>
                        </TD>
                        <TD className="text-muted-foreground text-xs">
                          <span className="line-clamp-1" title={c.domains.join(", ")}>
                            {c.domains.join(", ")}
                          </span>
                        </TD>
                        <TD className="tabular text-right whitespace-nowrap">
                          {c.days_left == null ? "—" : `${c.days_left} 天`}
                        </TD>
                        <TD>
                          <StatusBadge state={s.state}>{s.text}</StatusBadge>
                        </TD>
                      </TR>
                    );
                  })}
                </TBody>
              </Table>
            )}
          </CardContent>
        </Card>

        <div className="grid items-start gap-4 sm:grid-cols-2 xl:grid-cols-1">
          <Card>
            <CardHeader>
              <CardTitle>到期分布</CardTitle>
              <CardDescription>未来 90 天，按周分桶。</CardDescription>
            </CardHeader>
            <CardContent>
              {issued === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-xs">
                  还没有已签发的证书，签发后这里会显示到期是否集中在某一周。
                </p>
              ) : (
                <>
                  <div className="flex h-24 gap-1" role="img" aria-label="未来 90 天证书到期分布">
                    {d.buckets.map((n, i) => {
                      const max = Math.max(...d.buckets, 1);
                      return (
                        // 外层撑满高度，内层的百分比高度才有参照
                        <div key={i} className="bg-muted flex h-full flex-1 flex-col justify-end rounded-sm">
                          <div
                            className={"w-full rounded-sm " + (i < 4 ? "bg-warn" : "bg-muted-foreground/40")}
                            style={{ height: `${(n / max) * 100}%`, minHeight: n ? 4 : 0 }}
                            title={`第 ${i + 1} 周：${n} 张`}
                          />
                        </div>
                      );
                    })}
                  </div>
                  <p className="text-muted-foreground mt-2.5 text-xs">
                    前四周标为琥珀色，是需要提前安排的区间。
                  </p>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>最近任务</CardTitle>
              <CardDescription>点击查看完整执行日志。</CardDescription>
            </CardHeader>
            <CardContent className="pt-2">
              {d.recent_jobs.length === 0 ? (
                <p className="text-muted-foreground py-6 text-center text-xs">还没有任务运行过。</p>
              ) : (
                <div className="-mx-2 space-y-0.5">
                  {d.recent_jobs.slice(0, 6).map((j) => {
                    const s = jobStatus(j);
                    return (
                      <Link
                        key={j.id}
                        to={`/jobs/${j.id}`}
                        className="hover:bg-accent flex items-center justify-between gap-2 rounded-md px-2 py-1.5"
                      >
                        <span className="min-w-0 truncate text-xs">
                          <span className="tabular text-muted-foreground">#{j.id}</span>{" "}
                          {j.kind} · {stageName(j.stage)}
                        </span>
                        <StatusBadge state={s.state}>{s.text}</StatusBadge>
                      </Link>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </>
  );
}
