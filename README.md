# vpn-sub — 自建实测订阅（v3 融合版）

从多个公开免费节点源聚合候选，用 mihomo 内核逐个做真实代理请求实测，
只保留活着的节点，按「双验 → 国内可用性分层 → 延迟」排序产出订阅。
GitHub Actions 每小时自动重测并更新本仓库的 `output/`。

## 订阅地址

- 分享链接版（明文）：https://raw.githubusercontent.com/artai8/vpn-sub/main/output/sub.txt
- 分享链接版（Base64）：https://raw.githubusercontent.com/artai8/vpn-sub/main/output/sub_base64.txt
- Clash 完整配置（分组 + 分流）：https://raw.githubusercontent.com/artai8/vpn-sub/main/output/clash.yaml
- 每轮实测报告：[output/report.md](output/report.md)

## 节点来源

- igareck/vpn-configs-for-russia 黑名单三件套（链接）
- aneek0/goida-vpn-configs 的 1/3/4/5 号聚合（链接）
- free-proxy-airport 的 4 个 Clash 原生源：openRunner、snakem982/proxypool、
  Flikify/Free-Node、free-clash-v2ray（YAML，主+备地址）

## 检测方法（v3）

1. 全部来源统一转成 Clash proxy 条目，指纹去重。
2. 按国内可用性分层排序：Reality > TLS+CDN 传输（ws/grpc/h2）> TLS 直连 >
   Shadowsocks > UDP 类（hysteria2/tuic）> 明文；单轮最多测 8000 个。
3. 用 mihomo 内核的 delay 接口逐个实测：先请求目标 A，通过者再请求目标 B
   复测（双验），只有真实代理请求成功才算存活。
4. 产出：sub.txt / sub_base64.txt（分享链接，最多 500 条）+ clash.yaml
   （完整配置：AUTO-FAST、HK/JP/SG/US 地区池、AI-POOL、FALLBACK 分组，
   OpenAI/ChatGPT/Claude 域名走 AI 池、国内 IP 直连）。
5. 自愈：某轮存活数异常低（<30）时不覆盖旧订阅。

说明：测试在 GitHub 机房（美国）执行，能剔除全球已死的节点并按经验规则
优先国内更可能可用的类型；单个节点在你的网络下是否可用，请以客户端实测为准。
免费公共节点由未知第三方运营，不要用来传输敏感数据。
