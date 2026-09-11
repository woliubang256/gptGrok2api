# 工作规则

1. 编码前先描述方案并等待批准，需求不明时提出澄清问题
2. 修改超 3 个文件的任务需先分解成更小单元
3. 代码完成后列出潜在问题并提供测试用例
4. 发现 bug 时先编写复现测试，修复至测试通过
5. 每次被纠正后在 AGENTS.md 添加新规则避免重复错误
6. 插件在界面消失时，先检查 ~/.codex/config.toml 的 [marketplaces] 配置是否完整，再用 `codex plugin list`、`codex plugin add` 验证 Chrome/Browser 是否安装并 enabled
7. 将源仓库 PR 合并到用户 fork 时，先确认 PR base 与 fork 分支，再将 PR head 合并到 fork 的目标分支；不得把合并请求误操作到源仓库
