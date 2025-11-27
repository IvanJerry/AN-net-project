# coding=utf-8
# 提取连续TCP包的特征：Payload（含TCP头部分，不包括端口和序列号）、Payload长度、时间间隔、TTL、IPFlag、TCPFlag
import glob
from scapy.all import PcapReader
import numpy as np
import binascii
from tqdm import tqdm
import os
import json
import argparse


def extract(payload):
    dic = {payload.name: payload}
    payload = payload.payload
    while payload.name != "NoPayload":
        dic[payload.name] = payload
        payload = payload.payload
    return dic


parser = argparse.ArgumentParser(description="Extract RawData from PCAPs for CipherSpectrum/ISCXVPN/ISCXTor")
parser.add_argument("--dataset", type=str, default="all",
                    choices=["CipherSpectrum", "ISCXVPN", "ISCXTor", "all"],
                    help="which dataset to extract (default: all as defined in dataset_config.json)")
parser.add_argument("--cipher_root", type=str, default=None,
                    help="override root path for CipherSpectrum (dataset 0)")
parser.add_argument("--vpn_root", type=str, default=None,
                    help="override root path for ISCXVPN (dataset 1)")
parser.add_argument("--tor_root", type=str, default=None,
                    help="override root path for ISCXTor (dataset 2)")

args = parser.parse_args()

with open("dataset_config.json", "r", encoding="utf-8") as f:
    dataset_config = json.load(f)

# 根据命令行参数可选地覆盖三个数据集的 root
if args.cipher_root is not None and "0" in dataset_config:
    dataset_config["0"]["root"] = args.cipher_root
if args.vpn_root is not None and "1" in dataset_config:
    dataset_config["1"]["root"] = args.vpn_root
if args.tor_root is not None and "2" in dataset_config:
    dataset_config["2"]["root"] = args.tor_root


for ds_id, ds_info in dataset_config.items():
    # 只处理 0/1/2 三个数据集
    if ds_id not in ["0", "1", "2"]:
        continue
    root = ds_info["root"]
    dataset_name = ds_info["name"]

    # 如果指定了单个数据集，只处理对应名称的那一个
    if args.dataset != "all" and dataset_name != args.dataset:
        continue
    dataset_prefix = f"{ds_id}_{dataset_name}"

    pcap_files = glob.glob(os.path.join(root, "*", "*.pcap")) + glob.glob(os.path.join(root, "*", "*.cap"))

    for filename in tqdm(pcap_files, desc=f"Processing dataset {dataset_prefix}"):
        # 只去掉最后一个扩展名，保留中间的 .pcap.TCP_... 等部分
        basename = os.path.basename(filename).rsplit(".", 1)[0]
        cls_name = os.path.basename(os.path.dirname(filename))
        new_dir = os.path.join("RawData", dataset_prefix, cls_name)
        if not os.path.isdir(new_dir):
            os.makedirs(new_dir)
        with PcapReader(filename) as fdesc:
            length_sequence = []
            time_sequence = []
            ttl_sequence = []
            ip_flag_sequence = []
            tcp_flag_sequence = []
            ip_total_length_sequence = []
            packet_raw_string_sequence = []
            # 方向指示符：client->server 记为 1，server->client 记为 -1，无法确定为 0
            direction_sequence = []
            client_ip, client_port = None, None
            server_ip, server_port = None, None
            while True:
                try:
                    packet = fdesc.read_packet()
                    result = extract(packet)
                    if "TCP" in result:
                        time = float(packet.time)
                        if result["TCP"].payload.name == "NoPayload":
                            length = 0
                        else:
                            length = len(result["TCP"].payload)
                        ttl = result["IP"].ttl
                        ip_total_len = result["IP"].len
                        data = (binascii.hexlify(bytes(result["TCP"])))
                        packet_string = data.decode()[24:24 + 128 * 2 + 2]
                        ip_flag = result["IP"].flags.value
                        tcp_flag = result["TCP"].flags.value

                        # 基于首个 TCP 包推断 client/server：假定端口较大的一端为 client
                        src_ip = result["IP"].src
                        dst_ip = result["IP"].dst
                        src_port = int(result["TCP"].sport)
                        dst_port = int(result["TCP"].dport)
                        if client_ip is None:
                            if src_port != dst_port:
                                if src_port > dst_port:
                                    client_ip, client_port = src_ip, src_port
                                    server_ip, server_port = dst_ip, dst_port
                                else:
                                    client_ip, client_port = dst_ip, dst_port
                                    server_ip, server_port = src_ip, src_port
                        # 根据当前包方向打标签
                        direction = 0
                        if client_ip is not None:
                            if src_ip == client_ip and src_port == client_port and dst_ip == server_ip and dst_port == server_port:
                                direction = 1
                            elif src_ip == server_ip and src_port == server_port and dst_ip == client_ip and dst_port == client_port:
                                direction = -1

                        time_sequence.append(time)
                        length_sequence.append(length)
                        packet_raw_string_sequence.append(packet_string)
                        ttl_sequence.append(ttl)
                        ip_flag_sequence.append(ip_flag)
                        tcp_flag_sequence.append(tcp_flag)
                        ip_total_length_sequence.append(ip_total_len)
                        direction_sequence.append(direction)
                except EOFError:
                    break
        if len(time_sequence) > 0:
            time_sequence = np.array(time_sequence)
            time_sequence -= time_sequence[0]
            time_sequence = time_sequence[1:] - time_sequence[:-1]
            time_sequence = np.insert(time_sequence, 0, 0)

            length_sequence = np.array(length_sequence)
            packet_raw_string_sequence = np.array(packet_raw_string_sequence)
            ttl_sequence = np.array(ttl_sequence)
            ip_flag_sequence = np.array(ip_flag_sequence)
            tcp_flag_sequence = np.array(tcp_flag_sequence)
            ip_total_length_sequence = np.array(ip_total_length_sequence)
            direction_sequence = np.array(direction_sequence)

            np.save(os.path.join(new_dir, basename + "_L.npy"), length_sequence)
            np.save(os.path.join(new_dir, basename + "_T.npy"), time_sequence)
            np.save(os.path.join(new_dir, basename + "_P.npy"), packet_raw_string_sequence)
            np.save(os.path.join(new_dir, basename + "_O.npy"), ttl_sequence)
            np.save(os.path.join(new_dir, basename + "_F.npy"), ip_flag_sequence)
            np.save(os.path.join(new_dir, basename + "_C.npy"), tcp_flag_sequence)
            np.save(os.path.join(new_dir, basename + "_I.npy"), ip_total_length_sequence)
            np.save(os.path.join(new_dir, basename + "_D.npy"), direction_sequence)
