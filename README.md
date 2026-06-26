# RKPPMVLite V3.0 HTTP 移动后端说明

RKPPMVLite 是 RKPP 的单文件移动 HTTP 后端。运行时只需要 `rkpp\_live\_tools.py`。

> 本版（V2.1）在 V2.0 基础上完成了一次结合真实抓包的整改，核心变化见文末「本版变更」。

## 当前能力

* 自动等待 `0x1002` 会话 Key，或使用 `--key` 指定 16 字节 ASCII / 32 位 hex Key。
* 会话 Key 只保存在运行内存中；启动时兼容读取旧 `key.txt`。
* `0x4013` 使用 `Ivdecoder` 固定 IV 解密路径，按 `tsf4g` trailer 去尾（`N ∈ \[6,22]`）。
* **同时解析 s2c 与 c2s 两个方向**：s2c 输出服务器驱动的场景/角色移动，c2s 输出玩家自身的移动请求。
* 只解码移动相关 opcode 和 proto。
* 只提供本地 HTTP / NDJSON relay，不输出 CSV，不使用 `out-dir`。

## 启动方式

实时抓包：

```powershell
python .\\rkpp\_live\_tools.py --iface "以太网" --port 8195 --relay-host 127.0.0.1 --relay-port 8765
```

已知 Key：

```powershell
python .\\rkpp\_live\_tools.py --iface "以太网" --port 8195 --key 59484438426252355a494e7467545057
```

离线回放：

```powershell
python .\\rkpp\_live\_tools.py --read-pcap .\\live\_capture.pcap --key 59484438426252355a494e7467545057 --relay-port 8765
```

无参数启动时会进入交互式模式。

### 命令行参数

|参数|默认|说明|
|-|-|-|
|`--iface`|—|抓包网卡名（实时模式必填其一）|
|`--read-pcap`|—|离线回放的 pcap 路径|
|`--port`|`8195`|目标游戏端口|
|`--key`|—|已知 Key（16 字节 ASCII 或 32 位 hex）；不填则等待 `0x1002` 自动获取|
|`--relay-host`|`127.0.0.1`|HTTP relay 监听地址|
|`--relay-port`|`8765`|HTTP relay 监听端口（被占用时自动向后回退）|
|`--relay-history`|`500`|`/latest` 与新连接回放保留的事件条数|
|`--no-bpf`|关|关闭 BPF 过滤（抓全部流量后自行筛选）|
|`--interactive`|关|进入交互提示（无参数启动时默认进入）|

## HTTP 接口

* `GET /health`：返回服务状态与运行计数。
* `GET /latest?limit=50`：返回最近一批移动事件（JSON 数组）。
* `GET /events`：返回 NDJSON 实时流，每行一个移动事件；新连接会先回放最近历史再转入实时（已做内部去重，不会重复推送）。

`/health` 主要字段：

```json
{
  "status": "ok", "mode": "move", "time": "...",
  "events": 0, "history": 0, "clients": 0, "dropped\_client\_events": 0,
  "packets": 0, "key\_hits": 0, "rows": 0,
  "parsed": 0, "failed": 0, "decode\_errors": 0, "listener\_errors": 0,
  "has\_key": false, "flows": 0, "flow\_expirations": 0, "flow\_ttl\_seconds": 0
}
```

事件中的 `event\_class` 用于区分 `client\_move`、`server\_move`、`scene\_action`、`scene\_actor`、`status` 和 `request`。每条事件含 `to\_pos` / `to\_rot` 等位姿字段、`summary\_text` 摘要，以及来源 `flow\_id`、`seq`、`opcode` 等。

## 移动事件范围

默认关注移动和场景动作相关数据：

* `ZoneScenePlayActsNotify (0x0414)` · s2c
* `ZoneScenePlayActsBatchNotify (0x0413)` · s2c
* `ZoneSceneMoveReq (0x0133)` · c2s（玩家自身移动）
* `ZoneSceneInteractMoveReq (0x03E8)` · c2s
* `ZoneSceneSyncPlayerStatusReq (0x0159)` · c2s
* `ZoneSceneChangeMoveModeReq (0x0360)` · c2s
* `ZoneSceneRelationTravelTogetherSyncReq (0x15E5)` · c2s
* 以及 `SpaceActionCollection` / `SpaceAct\_ClientMove` / `SpaceAct\_ServerMove` / `Position` / `SpaceBaseData` 等内部结构

其它非移动协议不作为本工具的默认输出范围。

## 运行依赖

* Python 3.11+
* `scapy`
* `pycryptodome`

```powershell
python -m pip install scapy pycryptodome
```

使用边界

本项目仅用于学习、协议研究、离线复现与安全研究，不支持用于外挂、破坏游戏环境或其他违规用途。

