# AGENTS.md

本仓库的编码智能体指引。

## 项目概览

这是 Mihomo Meta 内核，一个基于 Go 的代理和 DNS 服务。主入口为 `main.go`；
核心包按领域组织，包括 `dns`、`config`、`hub`、`adapter`、`listener`、`transport` 和 `tunnel`。

## 常用命令

- 格式化修改过的 Go 文件：`gofmt -w <文件>`
- 运行 DNS 包测试：`go test ./dns`
- 运行全部 Go 测试：`go test ./...`
- 构建本地默认二进制：`go build -tags with_gvisor`
- 使用项目标志构建 macOS arm64：`make darwin-arm64`
- Makefile 目标构建产物会写入 `bin/` 目录。

## 开发说明

- 优先使用现有包模式和辅助函数，而非引入新的抽象。
- 将变更范围限定在所需行为内，避免无关的格式变动。
- 在触及共享行为时更新或新增针对性测试，尤其是 DNS、配置解析、缓存行为以及路由/执行器代码。
- 当修改面向用户的配置时，需同步更新解析结构体和传播路径，并考虑是否需要在 `docs/config.yaml` 中添加示例。
- DNS 响应可能包含 `Extra` 中的 EDNS OPT 伪记录；不要将 OPT 记录的 TTL 字段视为普通缓存 TTL。
- 新增功能时优先创建新的独立代码文件，而非修改既有文件，以降低与上游合并时的冲突风险。

## 审查与验证

在交付代码变更前，先运行最小相关测试。对于 DNS 变更，`go test ./dns` 通常是最快的有效检验方式。
若变更涉及跨包契约或配置加载，则优先在时间允许时运行 `go test ./...`。

使用 `git diff --check` 检查空白问题后再合入变更。
