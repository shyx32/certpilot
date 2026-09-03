# 集成测试用的目标机：一台同时跑 sshd 与 nginx 的「服务器」。
#
# 用它来验证 CertPilot 的探测与部署链路，而不必真的准备一台机器。
FROM nginx:1.27-alpine

RUN apk add --no-cache openssh-server openssh-keygen openssl sudo

RUN ssh-keygen -A \
 && adduser -D -s /bin/sh deploy \
 && passwd -u deploy \
 && mkdir -p /home/deploy/.ssh \
 && chmod 700 /home/deploy/.ssh

# deploy 用户能写证书目录，但 nginx 主进程以 root 运行——
# 这正是生产里最常见的组合：写文件不需要提权，重载需要。
RUN mkdir -p /etc/nginx/certs/test.local \
 && chown -R deploy:deploy /etc/nginx/certs \
 && echo 'deploy ALL=(ALL) NOPASSWD: /usr/sbin/nginx' > /etc/sudoers.d/deploy \
 && chmod 440 /etc/sudoers.d/deploy

# 起始自签证书，让 nginx 能先跑起来；CertPilot 之后会替换它
RUN openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
      -subj "/CN=bootstrap" \
      -keyout /etc/nginx/certs/test.local/privkey.pem \
      -out   /etc/nginx/certs/test.local/fullchain.pem \
 && chown deploy:deploy /etc/nginx/certs/test.local/*

COPY site.conf /etc/nginx/conf.d/default.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22 443
ENTRYPOINT ["/entrypoint.sh"]
