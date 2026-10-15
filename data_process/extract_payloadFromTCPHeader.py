#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import csv
import json
import random
import numpy as np
import scapy.all as scapy
from flowcontainer.extractor import extract

import os,random,json,csv
import ipaddress,pickle

# generate random ipv4 address
def random_ipv4():
    IPV4_MAX = ipaddress.IPv4Address._ALL_ONES
    ip_int = random.randint(0, IPV4_MAX)
    ip_str = ipaddress.IPv4Address._string_from_ip_int(ip_int)
    return ip_str

# generate random ipv6 address
def random_ipv6():
    IPV6_MAX = ipaddress.IPv6Address._ALL_ONES
    ip_int = random.randint(0, IPV6_MAX)
    ip_str = ipaddress.IPv6Address._string_from_ip_int(ip_int)
    return ip_str

def random_field(bits):
    field_max = 2**bits-1
    field_int = random.randint(0, field_max)
    return field_int


import pdb
random.seed(40)

# ========= 参数配置 =========
pcap_root = "/3241903007/workstation/AnomalyTrafficDetection/dataset/ISCX-VPN-NonVPN-2016/datasets/flow_service"

input_dirs = [
    os.path.join(pcap_root, d)
    for d in os.listdir(pcap_root)
    if os.path.isdir(os.path.join(pcap_root, d))
]

output_dir = "/3241903007/workstation/AnomalyTrafficDetection/MutilFlow/datasets/own_lyj/ISCX-VPN-6-Service/data_5_25_PayloadFromTCPHeader"

output_csv = os.path.join(output_dir, "all_flows.csv")
os.makedirs(output_dir, exist_ok=True)

if not os.path.exists(output_csv):
    with open(output_csv, "w", newline="") as f:
        csv.writer(f).writerow(["label", "lengths", "directions", "iats", "payloads"])

# 提取阶段保存前 40 个包
max_packets = 40
payload_pac = 40
payload_len = 64

MAX_FLOWS_PER_LABEL = 500


def extract_packet_payload(packet):
    """
    只提取 TCP/UDP payload，不包含 Ethernet/IP/TCP/UDP header。
    ACK 空包返回 ""。
    """
    import pdb
    if scapy.IP not in packet:
        return None
    
    #返回整个payload
    #cpdb.set_trace()
    if scapy.TCP in packet:
        return bytes(packet[scapy.TCP]).hex()[8:]

    if scapy.UDP in packet:
        return bytes(packet[scapy.UDP]).hex()[8:]
    #return None


def random_ip_port(packets:scapy.PacketList):
    if len(packets) > 0:
        if scapy.IP in packets[0]:
            client_ip = packets[0][scapy.IP].src
            server_ip = packets[0][scapy.IP].dst
            r_client_ip = random_ipv4()
            r_server_ip = random_ipv4()
        elif scapy.IPv6 in packets[0]:
            client_ip = packets[0][scapy.IPv6].src
            server_ip = packets[0][scapy.IPv6].dst
            r_client_ip = random_ipv6()
            r_server_ip = random_ipv6() 
            
        else:
            print("other L3 protocol")
        r_client_port = random_field(16)
        r_server_port = random_field(16)
    else:
        print("No packet in the pcap file")
        return -1

    for packet in packets:
        if scapy.IP in packet:
            is_client = packet[scapy.IP].src==client_ip
            packet[scapy.IP].src = r_client_ip if is_client else r_server_ip
            packet[scapy.IP].dst = r_server_ip if is_client else r_client_ip
            if scapy.TCP in packet:
                packet[scapy.TCP].sport = r_client_port if is_client else r_server_port
                packet[scapy.TCP].dport = r_server_port if is_client else r_client_port
            if scapy.UDP in packet:
                packet[scapy.UDP].sport = r_client_port if is_client else r_server_port
                packet[scapy.UDP].dport = r_server_port if is_client else r_client_port
        if scapy.IPv6 in packet:
            is_client = packet[scapy.IPv6].src==client_ip
            packet[scapy.IPv6].src = r_client_ip if is_client else r_server_ip
            packet[scapy.IPv6].dst = r_server_ip if is_client else r_client_ip
            if scapy.TCP in packet:
                packet[scapy.TCP].sport = r_client_port if is_client else r_server_port
                packet[scapy.TCP].dport = r_server_port if is_client else r_client_port
            if scapy.UDP in packet:
                packet[scapy.UDP].sport = r_client_port if is_client else r_server_port
                packet[scapy.UDP].dport = r_server_port if is_client else r_client_port
    
    return packets

def get_flow_features(pcap_path, max_packets=40):
    length_list = []
    iat_list = []
    dir_list = []
    hexdata_list = []
    total_packets = 0

    print("pcap_file_path:-------------------------------------")
    print(pcap_path)

    try:
        packets = scapy.rdpcap(pcap_path)
        packets_info = {}
        
        #pdb.set_trace()

        # timestamp -> 去头部后的 payload
        # 有 payload：hex string
        # ACK 空包：""，用于保持 packet-level alignment
        
        #packets = random_ip_port(packets)
        
        #import pdb
        #pdb.set_trace()
        for packet in packets:
            if scapy.IP not in packet or (scapy.TCP not in packet and scapy.UDP not in packet):
                continue

            packet_timestamp = f"{packet.time:.6f}"
            payload_hex = extract_packet_payload(packet)

            if payload_hex is None:
                continue

            packets_info[packet_timestamp] = payload_hex

        print(f"packets length: {len(packets)}")
        print(f"tcp/udp packets indexed: {len(packets_info)}")

        # 先尝试 TCP flow
        try:
            feature_result = extract(
                pcap_path,
                filter="tcp",
                #extension=["data.data"],
                split_flag=False
            )
            print("TCP extraction succeeded, flows:", len(feature_result))
        except Exception as e:
            print(f"TCP extraction failed for {pcap_path}: {e}")
            feature_result = {}

        # 如果没有 TCP flow，再尝试 UDP flow
        if not feature_result:
            try:
                feature_result = extract(
                    pcap_path,
                    filter="udp",
                    #extension=["data.data"],
                    split_flag=False
                )
                print("UDP extraction succeeded, flows:", len(feature_result))
            except Exception as e:
                print(f"UDP extraction failed for {pcap_path}: {e}")
                return -1, 0, 0

        if not feature_result:
            return -1, 0, 0

        print("feature_result keys:", feature_result.keys())
        #import pdb
        #pdb.set_trace()
        for flow_key, flow_obj in feature_result.items():
            total_packets += len(flow_obj.ip_lengths)

            raw_lengths = np.array(flow_obj.ip_lengths[:max_packets]).tolist()
            raw_directions = [int(np.sign(x)) for x in flow_obj.ip_lengths[:max_packets]]
            raw_timestamps = np.array(flow_obj.ip_timestamps[:max_packets])

            if len(raw_lengths) == 0:
                continue

            # ===== 统计特征：保留前 40 个原始包 =====
            lengths = [abs(x) for x in raw_lengths]
            directions = raw_directions
            timestamps = raw_timestamps

            # ===== Payload：与前 40 个原始包逐包对齐 =====
            flow_data_list = []

            for ts in raw_timestamps[:payload_pac]:
                key = f"{ts:.6f}"
                payload_hex = packets_info.get(key, "")

                if payload_hex == "":
                    packet_bigram = ""
                else:
                    packet_bigram = bigram_generation(
                        payload_hex,
                        packet_len=payload_len,
                        flag=True
                    )

                flow_data_list.append(packet_bigram)

            # flow 少于 40 个包时，不强制补到 40；训练读取时会 PAD
            while len(flow_data_list) < len(lengths):
                flow_data_list.append("")

            # ===== IAT：基于原始前 40 个包计算 =====
            iats = np.diff(timestamps).tolist() if len(timestamps) > 1 else [0]
            iats = [round(i * 100, 1) for i in iats]
            iats.insert(0, 0.0)

            length_list.append(lengths)
            iat_list.append(iats)
            dir_list.append(directions)
            hexdata_list.append(flow_data_list)

            print(f"\n[DEBUG] flow_key: {flow_key}")
            print(f"Original packet count used: {len(raw_lengths)}")
            print(f"Lengths count: {len(lengths)}")
            print(f"Directions count: {len(directions)}")
            print(f"IATs count: {len(iats)}")
            print(f"Payload aligned count: {len(flow_data_list)}")
            print(f"Empty payload count: {sum(1 for x in flow_data_list if x == '')}")

        return (length_list, dir_list, iat_list, hexdata_list), total_packets, pcap_path

    except Exception as e:
        print(f"Error processing {pcap_path}: {e}")
        return -1, 0, 0


def mark_processed(log_file_path, pcap_file):
    os.makedirs(os.path.dirname(log_file_path), exist_ok=True)

    with open(log_file_path, "a") as f:
        json.dump({"file": pcap_file}, f)
        f.write("\n")


def get_processed_pcapfile(log_file_path):
    processed_files = []

    if os.path.exists(log_file_path):
        with open(log_file_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                try:
                    obj = json.loads(line)
                    processed_files.append(obj["file"])
                except json.JSONDecodeError:
                    continue

    return processed_files


def cut(obj, sec):
    result = [obj[i:i + sec] for i in range(0, len(obj), sec)]

    try:
        remanent_count = len(result[0]) % 4
    except Exception:
        remanent_count = 0
        print("cut datagram error!")

    if remanent_count != 0:
        result = [
            obj[i:i + sec + remanent_count]
            for i in range(0, len(obj), sec + remanent_count)
        ]

    return result


def bigram_generation(packet_datagram, packet_len=64, flag=True):
    result = ""
    generated_datagram = cut(packet_datagram, 1)
    token_count = 0

    for sub_string_index in range(len(generated_datagram)):
        if sub_string_index != len(generated_datagram) - 1:
            token_count += 1

            if token_count > packet_len:
                break

            merge_word_bigram = (
                generated_datagram[sub_string_index]
                + generated_datagram[sub_string_index + 1]
            )
        else:
            break

        result += merge_word_bigram
        result += " "
    #import pdb
    #pdb.set_trace()
    return result


def append_flow_csv(csv_path, label, lengths, directions, iats, payloads):
    with open(csv_path, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            label,
            json.dumps(lengths),
            json.dumps(directions),
            json.dumps(iats),
            json.dumps(payloads)
        ])


def main():
    processed_log = os.path.join(output_dir, "processed_files.json")
    processed_pcap_files = get_processed_pcapfile(processed_log)

    label_info = {}
    total_files = 0

    for input_dir in input_dirs:
        label = os.path.basename(input_dir)
        label_info[label] = 0

    for input_dir in input_dirs:
        label = os.path.basename(input_dir)
        print(f"\n[+] Processing label: {label}")

        label_flow_cnt = 0

        all_pcaps = []
        for root, dirs, files in os.walk(input_dir):
            for file in files:
                if file.endswith(".pcap"):
                    all_pcaps.append(os.path.join(root, file))

        if len(all_pcaps) > MAX_FLOWS_PER_LABEL:
            selected_pcaps = random.sample(all_pcaps, MAX_FLOWS_PER_LABEL)
        else:
            selected_pcaps = all_pcaps

        for pcap_path in selected_pcaps:
            if pcap_path in processed_pcap_files:
                print(f"Already processed: {pcap_path}, skipping.")
                continue

            print(f"Processing file: {pcap_path}")

            feature_results, total_pcaps, fpath = get_flow_features(
                pcap_path,
                max_packets=max_packets
            )

            print(
                f"Feature extraction result for {pcap_path}: "
                f"{'Success' if feature_results != -1 else 'Failed'}"
            )

            if feature_results == -1:
                continue

            label_info[label] += 1
            total_files += 1

            lengths_list, dirs_list, iats_list, payloads_list = feature_results

            for idx in range(len(lengths_list)):
                append_flow_csv(
                    output_csv,
                    label=label,
                    lengths=lengths_list[idx],
                    directions=dirs_list[idx],
                    iats=iats_list[idx],
                    payloads=payloads_list[idx]
                )

                label_flow_cnt += 1

            mark_processed(processed_log, pcap_path)
            processed_pcap_files.append(pcap_path)

        print(f"[✓] Label {label} finished with {label_flow_cnt} flows")

    label_info_path = os.path.join(output_dir, "label_info.json")

    with open(label_info_path, "w") as f:
        json.dump({
            "total_files": total_files,
            "labels": label_info
        }, f, indent=4)

    print(f"[+] Label info saved to {label_info_path}")
    print(f"Total successful files: {total_files}")

    for label, count in label_info.items():
        print(f"{label}: {count} files")


if __name__ == "__main__":
    main()