# vpn-sub — 自建节点订阅（实测过滤版）

原料来自 [igareck/vpn-configs-for-russia](https://github.com/igareck/vpn-configs-for-russia) 的三份黑名单，
由 GitHub Actions 每 6 小时自动拉取最新版，用 sing-box 逐个节点发真实代理请求实测，
只保留存活节点并按延迟排序，自动提交回本仓库。

## 订阅地址

- 明文：https://raw.githubusercontent.com/artai8/vpn-sub/main/output/sub.txt
- Base64：https://raw.githubusercontent.com/artai8/vpn-sub/main/output/sub_base64.txt
- 每轮报告：[output/report.md](output/report.md)

## 说明

- 测试点在 GitHub 的美国机房：能剔除全球已死的节点，但某节点在你的网络下是否可用，以你设备实测为准。
- 名单含同端点同 UUID 的参数变体，去重后独立节点远少于原始条数，属正常现象。
- sing-box 1.14.4 不支持 xhttp 传输，这类节点无法实测，已在报告中如实标注为未测。
- 节点均为公开的未知运营者节点，不要用它传输敏感数据。
