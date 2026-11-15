# VPN 节点订阅实测报告（v3 融合版：多源 + mihomo 引擎 + 双验 + 分层 + Clash 分组）

- 测试开始：2026-11-15 08:55:50 CST；结束：2026-11-15 09:14:54 CST（耗时 1143 秒）
- 测试引擎：mihomo（MetaCubeX）delay 接口，双目标 http://www.gstatic.com/generate_204 + https://cp.cloudflare.com/generate_204
- 来源统计（解析后节点数）：{'BLACK_VLESS_RUS.txt': 158, 'BLACK_VLESS_RUS_mobile.txt': 142, 'BLACK_SS+All_RUS.txt': 154, 'goida-4.txt': 415, 'goida-5.txt': 172, 'goida-1.txt': 5130, 'goida-3.txt': 9565, 'openRunner': 0, 'snakem982': 62, 'Flikify': 0, 'free-clash-v2ray': 489}

## 总览

- 链接源原始链接：**17814**（协议分布 {'vless': 11588, 'vmess': 1481, 'hysteria2': 111, 'trojan': 984, 'ss': 2064, 'socks5': 1562, 'hy2': 10, 'tuic': 2, 'ssr': 12}）；合并全部来源后节点 16287
- 去重后唯一节点：**9793**（重复 6494）
- 实际实测：**8000**；存活：**1314**；存活率：**16.4%**
- 双验通过：**1255**；订阅按「双验 → 分层 → 延迟」排序，保留前 500 条
- 延迟（存活）：最快 26 ms｜中位数 385 ms｜P90 1772 ms｜最慢 5972 ms

## 分层（去重后 / 实测 / 存活）

| 层 | 去重后 | 实测 | 存活 |
|---|---|---|---|
| 0 Reality | 2642 | 2642 | 378 |
| 1 TLS+CDN传输 | 2463 | 2463 | 277 |
| 2 TLS直连 | 932 | 932 | 184 |
| 3 SS | 1057 | 1057 | 307 |
| 4 UDP类(hy2/tuic) | 80 | 80 | 27 |
| 5 明文/其他 | 2619 | 826 | 141 |

## 未实测 / 跳过说明

- 链接转换失败/不支持：2078 条（{'socks5': 1562, 'vless': 373, 'hysteria2': 9, 'ssr': 12, 'hy2': 8, 'ss': 53, 'trojan': 25, 'vmess': 36}；含 ssr/socks5 等未实现链接解析的协议，这类节点若来自 Clash 源仍会被测）。
- mihomo 引擎拒绝（配置不合法被隔离剔除）：30 条。
- 优先级截断未测：1793 条（超出单轮 8000 上限的低层节点，本轮未测，不代表其真实状态）。
- 存活但无法生成分享链接（仅 Clash 版包含）：0 条。

## 测试方法

全部候选写入一份 mihomo 配置启动内核，逐个调用其 delay 接口经该节点请求目标 URL，返回有效延迟记为通过；通过者再换第二个目标复测（双验）。只有真实代理请求成功才算活。

## 产出

- `output/sub.txt`：500 条存活节点分享链接（双验 → 分层 → 延迟排序）。
- `output/sub_base64.txt`：sub.txt 的整文件 Base64 版。
- `output/clash.yaml`：完整 Clash 配置（500 个节点 + AUTO/HK/JP/SG/US/AI 分组 + FALLBACK + AI 域名分流规则）。
