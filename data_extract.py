# coding=utf-8
# 提取连续TCP包的特征：Payload（含TCP头部分，不包括端口和序列号）、Payload长度、时间间隔、TTL、IPFlag、TCPFlag
import glob
from scapy.all import PcapReader
import numpy as np
import binascii
from tqdm import tqdm
import os
import json


def extract(payload):
    dic = {payload.name: payload}
    payload = payload.payload
    while payload.name != "NoPayload":
        dic[payload.name] = payload
        payload = payload.payload
    return dic


with open("dataset_config.json", "r", encoding="utf-8") as f:
    dataset_config = json.load(f)


for ds_id, ds_info in dataset_config.items():
    # 只处理 0/1/2 三个数据集
    if ds_id not in ["0", "1", "2"]:
        continue
    root = ds_info["root"]
    dataset_name = ds_info["name"]
    dataset_prefix = f"{ds_id}_{dataset_name}"

    pcap_files = glob.glob(os.path.join(root, "*", "*.pcap")) + glob.glob(os.path.join(root, "*", "*.cap"))

    for filename in tqdm(pcap_files, desc=f"Processing dataset {dataset_prefix}"):
        basename = os.path.basename(filename).split(".")[0]
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
            packet_raw_string_sequence = []
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
                        data = (binascii.hexlify(bytes(result["TCP"])))
                        packet_string = data.decode()[24:24 + 128 * 2 + 2]
                        ip_flag = result["IP"].flags.value
                        tcp_flag = result["TCP"].flags.value

                        time_sequence.append(time)
                        length_sequence.append(length)
                        packet_raw_string_sequence.append(packet_string)
                        ttl_sequence.append(ttl)
                        ip_flag_sequence.append(ip_flag)
                        tcp_flag_sequence.append(tcp_flag)
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

            np.save(os.path.join(new_dir, basename + "_L.npy"), length_sequence)
            np.save(os.path.join(new_dir, basename + "_T.npy"), time_sequence)
            np.save(os.path.join(new_dir, basename + "_P.npy"), packet_raw_string_sequence)
            np.save(os.path.join(new_dir, basename + "_O.npy"), ttl_sequence)
            np.save(os.path.join(new_dir, basename + "_F.npy"), ip_flag_sequence)
            np.save(os.path.join(new_dir, basename + "_C.npy"), tcp_flag_sequence)
