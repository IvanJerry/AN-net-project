# AN-net-project
对AN-Net特征处理和特征融合的优化
# 第一阶段：基线建立与单特征验证 (Version 1.x)
在此阶段，保持原始字节输入（Raw Bytes Input）不变（即包含TCP头部和部分负载的原始字节），仅改变统计特征（Statistical Features）的输入向量。
- Length：包长序列
- IAT：到达时间间隔（Inter-Arrival Time）
- TTL：IP 包的 Time-To-Live
- IPFlag：IP 头标志位
- TCPFlag：TCP 标志位
- Payload：报文负载字节序列（做了嵌入/编码）
