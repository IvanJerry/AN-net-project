# AN-net-project
对AN-Net特征处理和特征融合的优化
# 第一阶段：基线建立与单特征验证 (Version 1.x)
在此阶段，保持原始字节输入（Raw Bytes Input）不变（即包含TCP头部和部分负载的原始字节），仅改变统计特征（Statistical Features）的输入向量。
- Length：包长序列：这里的 length 是 ` len(result["TCP"].payload)`
- IAT：到达时间间隔（Inter-Arrival Time）
- TTL：IP 包的 Time-To-Live
- IPFlag：IP 头标志位
- TCPFlag：TCP 标志位
- Payload：报文负载字节序列（做了嵌入/编码）:取的是整个TCP层的原始字节（TCP包头+负载），但是TCP头是从第12个字节/第24个Hex字符开始取的，前 12 字节大致对应：源端口(2B) + 目的端口(2B) + 序列号(4B) + 确认号(4B)，再截取大约 128 字节左右的内容（代码里给了 258 个 hex 字符）。
## Version 1.1: 增加 IP 总长度 (Add IP Total Length)
- 特征变更： 在 v1.0 基础上，统计特征向量增加一维 IP Total Length。
- 提取方法： 直接从 IP 头部提取 Total Length 字段（包含 IP 头、TCP/UDP 头和 Payload 的总大小）。
- 理论依据： LiM 论文指出，TLS 1.3 协议下，加密包的长度和时序依然是泄露流量模式的关键特征 。
- 预期： 在 ISCXVPN 和 ISCXTor 上应该有提升，因为不同应用产生的包大小分布通常不同。
## Version 1.2: 增加方向指示符 (Add Direction)特征变更：
- 在 v1.0 基础上，统计特征向量增加一维 Directional Indicator。
- 实现： Client $\to$ Server 记为 1，Server $\to$ Client 记为 -1。
- 理论依据： TrafficFormer 强调流量数据的方向和顺序至关重要，因为它们定义了协议的交互逻辑。
- 预期： 这是一个强特征，预计在所有数据集上都能带来准确率提升。
Version,Description,Dataset 0 (CipherSpectrum),Dataset 1 (ISCXVPN),Dataset 2 (ISCXTor),结论/备注
v1.0,"Baseline (IAT, TTL + RawBytes)",待填,待填,待填,基准分数
v1.1,v1.0 + IP Total Length,待填,待填,待填,验证 LiM 的长度特征有效性
v1.2,v1.0 + Direction,待填,待填,待填,验证 TrafficFormer 的方向逻辑
