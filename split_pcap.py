import os
from tqdm import tqdm
import subprocess

def split_pcap_files():
    splitter = "/3241903007/workstation/AnomalyTrafficDetection/ConfusionModel/ShieldGPT/pcap_tool/splitter"
    flow_packet_num_dict = {
        "BROWSING": 60,
        "CHAT": 100,
        "AUDIO": 100,
        "VIDEO": 200,
        "FILE-TRANSFER": 300,
        "MAIL": 300,
        "P2P": 150,
        "VOIP": 100,
    }
    for label in flow_packet_num_dict.keys():
        filenames = list(filter(lambda x: x.endswith(".pcap") and x.startswith(label), 
                        os.listdir("/3241903007/workstation/AnomalyTrafficDetection/dataset/ISCX-Tor-NonTor-2017/pcap/Tor"))) # only consider Tor traffic, ignore NonTor
        filenames = [f"/3241903007/workstation/AnomalyTrafficDetection/dataset/ISCX-Tor-NonTor-2017/pcap/Tor/{x}" for x in filenames]
        for filename in tqdm(filenames):
            dir_name = os.path.join("/3241903007/workstation/AnomalyTrafficDetection/dataset/ISCX-Tor-NonTor-2017/pcap/flows", label)
            os.makedirs(dir_name, exist_ok=True)
            flow_prefix = os.path.basename(filename)[:-len(".pcap")]
            with open(os.path.join("/3241903007/workstation/AnomalyTrafficDetection/dataset/ISCX-Tor-NonTor-2017/pcap/flows", f"{flow_prefix}.log"), "w") as f:
                subprocess.run(f"{splitter} -i '{filename}' -o '{dir_name}' -p {flow_prefix}- -f five_tuple -l {flow_packet_num_dict[label]}",
                            shell=True, stdout=f, stderr=subprocess.STDOUT)

if __name__ == "__main__":
    split_pcap_files()