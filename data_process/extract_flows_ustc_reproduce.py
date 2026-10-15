from scapy.all import rdpcap, IP, TCP, wrpcap
from collections import defaultdict
import os
import pdb
from decimal import Decimal
from scapy.all import rdpcap, IP, TCP, UDP, wrpcap
from collections import defaultdict
import os

def get_normalized_five_tuple(pkt):
    """
    生成归一化的五元组key（保证双向流量归为同一个流）
    返回：(src_ip, src_port, dst_ip, dst_port, protocol) 或 None（非IP包）
    """
    if not IP in pkt:
        return None  # 过滤非IP数据包（如ARP）
    
    # 提取IP和端口信息
    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    src_port = dst_port = 0
    protocol = ""
    
    # 区分TCP/UDP协议
    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        protocol = "TCP"
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        protocol = "UDP"
    else:
        return None  # 仅处理TCP/UDP
    
    # 归一化：按IP+端口字典序排序，保证A→B和B→A归为同一个流
    if (src_ip, src_port) < (dst_ip, dst_port):
        return (src_ip, src_port, dst_ip, dst_port, protocol)
    else:
        return (dst_ip, dst_port, src_ip, src_port, protocol)

def split_multiple_connections_in_session(packets):
    """
    拆分同一个五元组下的多个独立TCP连接实例
    :param packets: 同一个五元组的所有TCP包（未排序）
    :return: 列表，每个元素是一个独立TCP连接的包列表
    """
    # 第一步：按时间戳排序（关键！保证包的时序正确）
    packets_sorted = sorted(packets, key=lambda p: p.time)
    
    # 第二步：拆分多个连接实例
    connections = []  # 存储最终拆分的多个连接
    current_connection = []  # 存储当前正在构建的连接包
    has_terminated = True    # 标记当前连接是否已终止（初始为True，等待新SYN）
    
    for pkt in packets_sorted:
        if TCP not in pkt:
            continue
        
        tcp_flags = pkt[TCP].flags
        # 1. 识别新连接的起始：纯SYN包（仅S，无A），且上一个连接已终止
        if 'S' in tcp_flags and 'A' not in tcp_flags and has_terminated:
            # 如果当前有未保存的连接（理论上不会，因为has_terminated为True），先保存
            if current_connection:
                connections.append(current_connection)
            # 开始新连接
            current_connection = [pkt]
            has_terminated = False
        # 2. 属于当前连接的包：非新SYN包，且当前连接未终止
        elif not has_terminated:
            current_connection.append(pkt)
            # 3. 识别连接终止：FIN或RST包
            if 'F' in tcp_flags or 'R' in tcp_flags:
                has_terminated = True
    
    # 4. 保存最后一个未终止但有数据的连接（避免遗漏）
    if current_connection and len(current_connection) > 0:
        connections.append(current_connection)
    
    # 过滤掉空连接或只有1个包的无效连接
    valid_connections = [conn for conn in connections if len(conn) >= 3]  # 至少3个包（三次握手）
    return valid_connections

def is_timestamp_interval_gt(ts1, ts2,time_step):
    dec_ts1 = Decimal(str(ts1))
    dec_ts2 = Decimal(str(ts2))
    return abs(dec_ts1 - dec_ts2) > Decimal(f'{str(time_step)}')

def create_folder_if_not_exists(folder_path):
    """
    检查文件夹是否存在，不存在则创建（单层）
    :param folder_path: 文件夹路径（如 "/mnt/ssd1/flows/BROWSING"）
    """
    # 检查文件夹是否存在
    if not os.path.exists(folder_path):
        try:
            # 创建单层文件夹（仅当父目录存在时生效）
            os.mkdir(folder_path)
            #print(f"文件夹创建成功：{folder_path}")
        except Exception as e:
            print(f"创建文件夹失败：{e}")

def split_complete_flows(pcap_path,flow_count,pref_fix,time_step=15, output_dir="flows"):
    """
    最终完整逻辑：先按五元组分大组，再拆分同五元组下的多个独立TCP连接
    """
    # 创建输出目录
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 1. 读取PCAP并按归一化五元组分大组
    all_packets = rdpcap(pcap_path)
    tcp_sessions = defaultdict(list)
    for pkt in all_packets:
        key = get_normalized_five_tuple(pkt)
        if key:
            tcp_sessions[key].append(pkt)
     
            
    
            
    for flow_idx, (flow_key, pkt_list) in enumerate(tcp_sessions.items(), 1):
        # 构造流的PCAP文件名（包含五元组信息，便于识别）
        src_ip, src_port, dst_ip, dst_port, protocol = flow_key
        pre_ts=0
        
        flow_packet_list=[]
        #过滤掉少于5个数据包的流
        if len(pkt_list)<5:
            continue
        for i in range(len(pkt_list)):
            packet = pkt_list[i]
            curr_ts = Decimal(str(packet.time))
            if i==0:
                pre_ts=curr_ts
            else:
                #print(curr_ts)
                if is_timestamp_interval_gt(curr_ts,pre_ts,time_step):
                    pre_ts=curr_ts
                    pcap_filename = f"{pref_fix}-{src_ip}_{src_port}_{dst_ip}_{dst_port}_{protocol}_{flow_count}.pcap"
                    base_dir = os.path.join(os.getcwd(),output_dir)
                    base_dir = os.path.join(base_dir,pref_fix)
                    create_folder_if_not_exists(base_dir)
                    pcap_path = os.path.join(base_dir, pcap_filename)
                    if len(flow_packet_list)<5:
                        continue
                    #print(f"write flow to file,flow packet length:{len(flow_packet_list)},flow counts:{flow_count+1}")
                    wrpcap(pcap_path, flow_packet_list)
                    flow_packet_list=[]
                    #pdb.set_trace
                    flow_count+=1
                    continue
                    #break
            flow_packet_list.append(packet)
                    

if __name__ == "__main__":
    input_pcap_dir = "/3241903007/daisy/dataset/USTC-TFC2016"

    output_dir = "/3241903007/workstation/AnomalyTrafficDetection/MutilFlow/datasets/splited/USTC"

    time_step = 15
    flow_count = 0

    for category in ["Benign", "Malware"]:
        category_dir = os.path.join(input_pcap_dir, category)

        # 每个子目录就是一个类别
        for label in sorted(os.listdir(category_dir)):
            label_dir = os.path.join(category_dir, label)

            if not os.path.isdir(label_dir):
                continue

            # 每个类别目录中的 PCAP
            for file in sorted(os.listdir(label_dir)):
                if not file.lower().endswith(".pcap"):
                    continue

                pcap_file = os.path.join(label_dir, file)

                print("=" * 80)
                print(f"Type  : {category}")
                print(f"Label : {label}")
                print(f"PCAP  : {pcap_file}")

                split_complete_flows(
                    pcap_file,
                    flow_count,
                    label,
                    time_step,
                    output_dir=output_dir
                )