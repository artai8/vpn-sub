# VPN 节点订阅实测报告（第一版）

- 测试开始：2026-11-14 21:48:31 CST；结束：2026-11-14 21:49:04 CST（耗时 33 秒）
- 测试工具：sing-box version 1.14.4（官方 GitHub release，linux-amd64）
- 源文件（igareck 黑名单，运行时拉取最新版）：BLACK_VLESS_RUS.txt, BLACK_VLESS_RUS_mobile.txt, BLACK_SS+All_RUS.txt
- 参数：并发 32，单节点超时 8s，块大小 110，TCP 预筛 开（3.5s）

## 总览

- 源文件链接行总数：**542**（按文件：{'BLACK_VLESS_RUS.txt': 299, 'BLACK_VLESS_RUS_mobile.txt': 150, 'BLACK_SS+All_RUS.txt': 93}）
- 支持协议的链接：542（vless 438，vmess 98，trojan 6）
- 去重后唯一节点：**108**（注：源列表含大量同端点同 UUID 的参数变体，如同一 Cloudflare 端点仅 fp/sni/备注不同，整行重复就达 139 条；按协议+服务器+端口+凭据去重后实际独立端点远少于 542）
- 实际完成代理实测（含预筛淘汰计死）：**108**；存活：**52**；存活率：**48.1%**

## 分协议

| 协议 | 去重后 | 进入实测流程 | 存活 |
|---|---|---|---|
| trojan | 3 | 3 | 1 |
| vless | 60 | 60 | 20 |
| vmess | 45 | 45 | 31 |

## 延迟（存活节点）

- 最快 79 ms｜中位数 489 ms｜P90 3737 ms｜最慢 7965 ms

## 未实测 / 跳过说明

- 链接转换失败：7 条（按协议：{'vless': 7}）。其中 xhttp 传输 7 条：sing-box 1.14.4 已移除/不含 xhttp(splithttp) 传输，已用两种类型名实测均被 `sing-box check` 拒绝，故未测。
- sing-box check 校验失败：0 条（按协议：{}），多为参数不完整/不合规范的公开配置，未进入实测。明细见 work/results.json 的 check_fail。
- ss：三份源文件本期快照中实际为 0 条（BLACK_SS+All 文件名虽含 SS，本期内容为 vmess/trojan），无可测样本。解析器已支持该协议。
- hysteria2：三份源文件本期快照中实际为 0 条（BLACK_SS+All 文件名虽含 SS，本期内容为 vmess/trojan），无可测样本。解析器已支持该协议。
- tuic：三份源文件本期快照中实际为 0 条（BLACK_SS+All 文件名虽含 SS，本期内容为 vmess/trojan），无可测样本。解析器已支持该协议。
- TCP 预筛淘汰：1 条（端口 TCP 不可达，直接计死，未再走代理请求；UDP 类协议不做预筛）。

## 测试方法

每条链接转 sing-box outbound 后先过 `sing-box check`；再分块启动单个 sing-box 进程，为每个节点建一个本地 mixed 入站并路由到对应 outbound，用 curl 经 SOCKS5 请求 `http://www.gstatic.com/generate_204`，失败再试 https 版，返回 200/204 记为存活，延迟为该次请求总耗时。只有代理请求成功才算活，端口通不算。

## 产出

- `output/sub.txt`：52 条存活节点原链接，按延迟升序。
- `output/sub_base64.txt`：sub.txt 的整文件 Base64 版。
- `work/results.json`：全部节点明细（状态/延迟/失败原因）、转换失败与校验失败清单。
