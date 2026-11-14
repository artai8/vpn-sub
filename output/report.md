# VPN 节点订阅实测报告（v2：多源合并 + 双目标验证 + 国内优先分层）

- 测试开始：2026-11-15 06:52:47 CST；结束：2026-11-15 07:06:40 CST（耗时 833 秒）
- 测试工具：sing-box version 1.14.4（官方 GitHub release，linux-amd64）
- 源文件（运行时拉取最新版）：BLACK_VLESS_RUS.txt, BLACK_VLESS_RUS_mobile.txt, BLACK_SS+All_RUS.txt, goida-4.txt, goida-5.txt, goida-1.txt, goida-3.txt
- 参数：并发 32，单节点超时 8s，块大小 110，TCP 预筛 开（3.5s）

## 总览

- 源文件链接行总数：**17921**（按文件：{'BLACK_VLESS_RUS.txt': 207, 'BLACK_VLESS_RUS_mobile.txt': 131, 'BLACK_SS+All_RUS.txt': 128, 'goida-4.txt': 399, 'goida-5.txt': 271, 'goida-1.txt': 6829, 'goida-3.txt': 9956}）
- 支持协议的链接：16277（vless 11613，ss 2085，vmess 1470，trojan 991，hysteria2 107，hy2 9，tuic 2）
- 未识别协议（跳过）：{'socks5': 1624, 'ssr': 11}
- 去重后唯一节点：**8647**（注：源列表含大量同端点同 UUID 的参数变体，如同一 Cloudflare 端点仅 fp/sni/备注不同，整行重复就达 139 条；按协议+服务器+端口+凭据去重后实际独立端点远少于 542）
- 实际完成代理实测（含预筛淘汰计死）：**4500**；存活：**548**；存活率：**12.2%**
- 双验通过（两个不同目标都请求成功）：**518**；订阅按「双验优先 → 分层（Reality > TLS+CDN传输 > TLS直连 > SS > UDP类 > 明文）→ 延迟」排序，保留前 500 条

## 分协议

| 协议 | 去重后 | 进入实测流程 | 存活 |
|---|---|---|---|
| hysteria2 | 78 | 0 | 0 |
| shadowsocks | 1050 | 0 | 0 |
| trojan | 410 | 257 | 91 |
| tuic | 2 | 0 | 0 |
| vless | 6297 | 3948 | 406 |
| vmess | 810 | 295 | 51 |

## 延迟（存活节点）

- 最快 35 ms｜中位数 498 ms｜P90 2913 ms｜最慢 7851 ms

## 未实测 / 跳过说明

- 链接转换失败：988 条（按协议：{'vless': 890, 'vmess': 36, 'ss': 54, 'hysteria2': 1, 'trojan': 7}）。其中 xhttp 传输 832 条：sing-box 1.14.4 已移除/不含 xhttp(splithttp) 传输，已用两种类型名实测均被 `sing-box check` 拒绝，故未测。
- sing-box check 校验失败：216 条（按协议：{'vless': 196, 'shadowsocks': 14, 'trojan': 6}），多为参数不完整/不合规范的公开配置，未进入实测。明细见 work/results.json 的 check_fail。
- TCP 预筛淘汰：1706 条（端口 TCP 不可达，直接计死，未再走代理请求；UDP 类协议不做预筛）。
- 优先级截断未测：3931 条（池子扩大后按国内可用性分层排序，超出单轮 4500 上限的部分本轮未测，不代表其真实状态）。

## 测试方法

每条链接转 sing-box outbound 后先过 `sing-box check`；再分块启动单个 sing-box 进程，为每个节点建一个本地 mixed 入站并路由到对应 outbound，用 curl 经 SOCKS5 请求 `http://www.gstatic.com/generate_204`，失败再试 https 版，返回 200/204 记为存活，延迟为该次请求总耗时。只有代理请求成功才算活，端口通不算。

## 产出

- `output/sub.txt`：500 条存活节点原链接，按「双验 → 分层 → 延迟」排序（本轮存活共 548 条，保留前 500 条）。
- `output/sub_base64.txt`：sub.txt 的整文件 Base64 版。
- `work/results.json`：全部节点明细（状态/延迟/失败原因）、转换失败与校验失败清单。
