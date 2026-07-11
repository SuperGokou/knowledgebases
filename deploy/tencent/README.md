# 腾讯云隔离部署运行手册

本目录用于将知识库部署到共享的腾讯云主机。生产编排只运行 Web、API、维护任务和反向代理；数据库、Redis 与对象存储继续使用受管服务。

## 隔离边界

- 固定使用独立 Compose 项目名 `heyi-kb-prod`。
- 仅公开高位 HTTPS 端口 `18443`，不占用宿主机 `80/443`。
- 网络、数据卷、镜像和日志均由 Compose 项目作用域隔离。
- 不修改 Docker 守护进程、系统代理或其他 Compose 项目。
- 环境变量文件位于发布目录之外，权限必须为 `0600`，且不得提交到 Git。

## 目录约定

```text
/srv/heyi-knowledgebases/
├── releases/<git-sha>/
│   └── deploy.env
└── shared/
    ├── api.env
    └── web.env
```

`deploy.env` 随发布版本保存固定的 Git SHA 镜像引用和共享密钥文件路径。回滚时必须使用目标发布目录自己的 `deploy.env`，不得使用其他版本的镜像引用。

## 常用操作

所有命令必须显式指定项目名、环境文件和编排文件：

```bash
sudo docker compose \
  --project-name heyi-kb-prod \
  --env-file /srv/heyi-knowledgebases/releases/<git-sha>/deploy.env \
  --file /srv/heyi-knowledgebases/releases/<git-sha>/deploy/tencent/compose.yml \
  ps
```

查看本项目日志时同样使用上述前缀并追加 `logs --tail=200 api web proxy maintenance`。禁止执行全局 `docker system prune`，也不要对不属于 `heyi-kb-prod` 的容器、网络或卷执行停止、删除操作。

首次在空机部署时可顺序构建 API 与 Web 镜像。共享主机开始承载其他应用后，应由 CI 构建带 Git SHA 的不可变镜像，服务器只执行 `pull` 和项目限定的 `up -d`，避免现场构建抢占其他应用的 CPU 与内存。

## HTTPS 说明

首次灰度使用 Caddy 内部 CA，为服务器 IP 提供加密访问，浏览器会显示证书未受公共机构信任。正式上线时应绑定企业域名，将本项目接入独立域名和公共 HTTPS 证书，再按变更窗口切换到 `443`。
