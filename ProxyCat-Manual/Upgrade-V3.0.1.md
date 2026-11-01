# 升级至 ProxyCat-V3.0.1

本分支以官方 `ProxyCat-V3.0.1`（`6cf3187`）为基准，包含内置代理池、多出口调度、新版管理面板、访问记录和版本检查。保留本分支的强制认证、密码哈希与 Windows UTF-8 启动入口。

## 升级步骤

1. 停止旧实例，完整备份部署目录，尤其是 `config/`、`logs/` 和 `modules/proxypool/data/`。
2. 更新源码，不要用仓库模板覆盖已有 `config/config.ini`，也不要复制其他部署的运行数据或凭据。
3. 使用 Python 3.10 或更高版本安装依赖：`python -m pip install -r requirements.txt`。
4. Windows 运行 `start.bat`；Linux/macOS 运行 `python3 app.py`。`app.py` 已包含代理服务，请只启动一个入口。
5. 面板默认端口为 `5001`，已有部署仍使用配置中的 `web_port`。首次打开 `/web?token=<管理Token>`，后续使用 HttpOnly Cookie；API 支持 Bearer、`X-ProxyCat-Token` 和原有查询参数。

## 凭据与配置

仓库模板不再附带公开 Token 或公共账号密码。优先使用已配置凭据，环境变量 `PROXYCAT_MANAGEMENT_TOKEN`、`PROXYCAT_PROXY_USERNAME` 和 `PROXYCAT_PROXY_PASSWORD` 可覆盖配置。代理环境用户名和密码必须同时设置。

缺少凭据时自动生成强随机管理 Token 及 `proxycat` 用户，保存在 Git 忽略的 `config/initial_credentials.txt`，配置文件不因生成凭据而改写。该文件在重启时会复用，请限制访问并保留；删除后缺少配置的凭据会重新生成。Web 保存的代理密码使用 scrypt 哈希，API 不回传密码。

正式环境启用 HTTPS，并设置 `management_cookie_secure=true`。`require_proxy_auth=true` 为默认策略；强制认证时无有效用户则拒绝监听。不要把本机真实 Token 提交到仓库。

新版启动入口保留上游的旧配置迁移：旧来源、代理数量等字段可能迁移为新版字段，并补齐代理池配置。升级前必须保留备份；本分支的凭据生成不会重写 INI。

## Docker

`docker compose up -d --build` 使用新版 Dockerfile。配置、日志、代理池数据通过卷保留，容器 UID/GID 需匹配宿主目录；`.env` 可设置凭据及 `PUID` / `PGID`。旧版映射为 5000 时按实际 `web_port` 调整 Compose 映射。停止宽限期保持 60 秒。

## 回滚

停止新版容器或进程，恢复升级前的源码、依赖环境和完整备份，再运行旧入口。数据库应与对应版本一起恢复，不要将新数据库直接交给旧版运行。此升级不重写已有发布 Tag。
