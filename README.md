# AN-net-project
对AN-Net特征处理和特征融合的优化
# 第一阶段：基线建立与单特征验证 (Version 1.x)
在此阶段，保持原始字节输入（Raw Bytes Input）不变（即包含TCP头部和部分负载的原始字节），仅改变统计特征（Statistical Features）的输入向量。
- [0] Length：包长序列：这里的 length 是 ` len(result["TCP"].payload)`
- [1] IAT：到达时间间隔（Inter-Arrival Time）
- [2] TTL：IP 包的 Time-To-Live
- [3] IPFlag：IP 头标志位
- [4] TCPFlag：TCP 标志位
- [5] Payload：报文负载字节序列（做了嵌入/编码）:取的是整个TCP层的原始字节（TCP包头+负载），但是TCP头是从第12个字节/第24个Hex字符开始取的，前 12 字节大致对应：源端口(2B) + 目的端口(2B) + 序列号(4B) + 确认号(4B)，再截取大约 128 字节左右的内容（代码里给了 258 个 hex 字符）。
## Version 1.1: 增加 IP 总长度 (Add IP Total Length)
- 特征变更： 在 v1.0 基础上，统计特征向量增加一维 IP Total Length。
- 提取方法： 直接从 IP 头部提取 Total Length 字段（包含 IP 头、TCP/UDP 头和 Payload 的总大小）。
- 理论依据： LiM 论文指出，TLS 1.3 协议下，加密包的长度和时序依然是泄露流量模式的关键特征 。
- 预期： 在 ISCXVPN 和 ISCXTor 上应该有提升，因为不同应用产生的包大小分布通常不同。
所以现在特征是：
- [0] Length：包长序列：这里的 length 是 ` len(result["TCP"].payload)`
- [1] IAT：到达时间间隔（Inter-Arrival Time）
- [2] IP Total Length   ← **新加**
- [3] TTL：IP 包的 Time-To-Live
- [4] IPFlag：IP 头标志位
- [5] TCPFlag：TCP 标志位
- [6] Payload (64 维)：报文负载字节序列（做了嵌入/编码）:取的是整个TCP层的原始字节（TCP包头+负载），但是TCP头是从第12个字节/第24个Hex字符开始取的，前 12 字节大致对应：源端口(2B) + 目的端口(2B) + 序列号(4B) + 确认号(4B)，再截取大约 128 字节左右的内容（代码里给了 258 个 hex 字符）。
## Version 1.2: 增加方向指示符 (Add Direction)特征变更：
- 在 v1.0 基础上，统计特征向量增加一维 Directional Indicator。
- 实现： Client $\to$ Server 记为 1，Server $\to$ Client 记为 -1。
- 理论依据： TrafficFormer 强调流量数据的方向和顺序至关重要，因为它们定义了协议的交互逻辑。
- 预期： 这是一个强特征，预计在所有数据集上都能带来准确率提升。
## version 2
[1] IP 总长度 (IP Total Length) IP 数据包的总大小（包含 IP 头 + TCP 头 + 荷载）。代码中通过 ip_layer.len 提取，用于替代旧版的 TCP 载荷长度，能捕捉由 TCP Options 引起的头部长度微小变化。
[2] 有效载荷长度 (Payload Length) 应用层纯数据的大小。提取逻辑为 IP 总长度减去 IP 头部长度和 TCP 头部长度，用于帮助模型解耦“数据大小”与“协议结构”。
[3] 到达时间间隔 (Inter-Arrival Time / IAT) 流的节奏，反映应用的突发性和自动化程度。代码中通过计算相邻数据包的时间戳差值得到 time_sequence。
[4] 生存时间 (Time To Live / TTL) 网络路径指纹，反映不同的操作系统默认初始 TTL 值。直接从 ip_layer.ttl 提取。
[5] 相对方向 (Relative Direction) 交互逻辑指示符，定义流量的“一来一回”节奏。提取时基于首包源 IP 进行判断：同首包 IP 为 1（Client），不同则为 2（Server）。
[6] IP 标志位 (IP Flags) IP 协议状态（如 DF 位）。提取自 ip_layer.flags.value。
[7] TCP 标志位 (TCP Flags) TCP 协议状态（如 SYN/ACK/PSH），标记流处于握手、传输还是断开阶段。提取自 tcp_layer.flags.value。
[8] 匿名化协议头 (Anonymized Protocol Header) 去噪后的协议结构字节（前 60 字节），仅包含 IP+TCP 头部，丢弃 Payload。代码中将 IP 地址和端口号位置置 0 以防作弊，并将其转换为整数序列供模型学习微观协议行为（如窗口大小）。
