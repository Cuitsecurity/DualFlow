'''
Handle the raw dataset
'''

import math
import os
import shutil
import scapy.all as scapy
from tqdm import tqdm

clean_protocols = '"not arp and not dns and not stun and not dhcpv6 and not icmpv6 and not icmp and not dhcp and not llmnr and not nbns and not ntp and not igmp"'

exact_5 = False # True represents each flow contains exact 5 packets

for p, d, f in os.walk('.'):
    for dir in d:
        print("----------")
        print(f'[{dir}]')
        print("----------")
        for pp, dd, ff in os.walk(os.path.join(p, dir)):
            for file in ff:
                print(file + '...')
                
                # rename pcapng as pcap
                if file.find('.pcapng') != -1:
                    shutil.move(os.path.join(pp, file), os.path.join(pp, file.replace('.pcapng', '.pcap')))
                    file = file.replace('.pcapng', '.pcap')
                org_file = os.path.join(pp, file)
                
                if exact_5:
                    # truncate pcap at 100000 packets
                    new_org_file = os.path.join(pp, file.replace('.pcap', '_100000.pcap'))
                    os.system(f"tcpdump -r {org_file} -w {new_org_file} -c 100000")
                    os.remove(org_file)
                    org_file = new_org_file
                
                # remove DHCP etc.
                clean_file = org_file.replace('.pcap', '.clean.pcap')
                os.system(f"tshark -F pcap -r {org_file} -Y {clean_protocols} -w {clean_file}")
                os.remove(org_file)
                shutil.move(clean_file, org_file)
                
                # split by session
                os.system(f"SplitCap.exe -r {org_file} -s session -o {org_file.replace('.pcap', '')} > /dev/null")
                os.remove(org_file)
                
                if not exact_5:
                    # each session contains at least 5 packets
                    for ppp, ddd, fff in os.walk(org_file.replace('.pcap', '')):
                        for file_ in fff:
                            pkts = scapy.rdpcap(os.path.join(ppp, file_), count=5)
                            if len(pkts) < 5:
                                os.remove(os.path.join(ppp, file_))
                        break
                else:
                    # each session contains exactly 5 packets
                    for ppp, ddd, fff in os.walk(org_file.replace('.pcap', '')):
                        for file_ in fff:
                            pkts = scapy.rdpcap(os.path.join(ppp, file_))
                            if len(pkts) < 5:
                                os.remove(os.path.join(ppp, file_))
                                continue
                            flow_num = math.floor(len(pkts) / 5)
                            for i in range(flow_num):
                                scapy.wrpcap(os.path.join(ppp, file_.replace('.pcap', f'_flow{i}.pcap')), pkts[i * 5: i * 5 + 5])
                            os.remove(os.path.join(ppp, file_))
                        break
            break
    break