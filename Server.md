# RKPPMVLite V2.0 HTTP 移动后端说明

RKPPMVLite 是 RKPP 的单文件移动 HTTP 后端。

## 当前能力

- 自动等待 `0x1002` 会话 Key，或使用 `--key` 指定 16 字节 ASCII / 32 位 hex Key。
- 会话 Key 只保存在运行内存中；启动时兼容读取旧 `key.txt`。
- `0x4013` 使用 `Ivdecoder` 固定 IV 解密路径。
- 只解码移动相关 opcode 和 proto。
- 只提供本地 HTTP / NDJSON relay，不输出 CSV，不使用 `out-dir`。

## 启动方式

实时抓包：

```powershell
python .\rkpp_live_tools.py --iface "以太网" --port 8195 --relay-host 127.0.0.1 --relay-port 8765
```

已知 Key：

```powershell
python .\rkpp_live_tools.py --iface "以太网" --port 8195 --key 59484438426252355a494e7467545057
```

离线回放：

```powershell
python .\rkpp_live_tools.py --read-pcap .\live_capture.pcap --key 59484438426252355a494e7467545057 --relay-port 8765
```

无参数启动时会进入交互式模式。

## HTTP 接口

- `GET /health`：返回服务状态、解析计数、flow 数、decode 错误数和慢客户端丢弃计数。
- `GET /latest?limit=50`：返回最近一批移动事件。
- `GET /events`：返回 NDJSON 实时流，每行一个移动事件。

事件中的 `event_class` 用于区分 `client_move`、`server_move`、`scene_action`、`scene_actor`、`status` 和 `request`。

## 移动事件范围

默认关注移动和场景动作相关数据：

- `ZoneScenePlayActsNotify (0x0414)`
- `ZoneScenePlayActsBatchNotify (0x0413)`
- `SpaceActionCollection.client_move`
- `SpaceAct_ClientMove`
- `Position`
- `SpaceBaseData`

其它非移动协议不作为本工具的默认输出范围。

## 运行依赖

- Python 3.11+
- `scapy`
- `pycryptodome`

```powershell
python -m pip install scapy pycryptodome
```

## 使用边界

本项目仅用于学习、协议研究、离线复现与安全研究，不支持用于外挂、破坏游戏环境或其他违规用途。
