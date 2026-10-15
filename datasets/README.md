# Datasets

MultiFlow evaluates four classification tasks using three public traffic collections. Download the original PCAP files from the providers below; this directory contains documentation only.

| Dataset / task | Classes | Train | Dev | Test | Download / provider |
|---|---:|---:|---:|---:|---|
| CSTNET-TLS-1.3 | 120 | 37,098 | 4,637 | 4,637 | [ET-BERT dataset release](https://github.com/linwhitehat/ET-BERT#datasets) |
| ISCX-VPN-Service | 6 | 1,780 | 222 | 222 | [UNB/CIC ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html) |
| ISCX-VPN-App | 14 | 2,695 | 337 | 337 | [UNB/CIC ISCXVPN2016](https://www.unb.ca/cic/datasets/vpn.html) |
| USTC-TFC | 20 | 6,032 | 754 | 754 | [USTC-TFC2016 repository](https://github.com/davidyslu/USTC-TFC2016) |

The split sizes above are reported in the MultiFlow paper after preprocessing. Provider downloads contain the original collection, not necessarily the exact MultiFlow sample selections or split CSVs.

## CSTNET-TLS-1.3

This dataset supports fine-grained encrypted application classification under TLS 1.3. MultiFlow uses 120 application classes.

- **Publisher:** [ET-BERT dataset release](https://github.com/linwhitehat/ET-BERT#datasets). The publisher describes an anonymized CSTNET TLS 1.3 collection.
- **Download status:** the publisher's linked `CSTNET-TLS 1.3/readme.md` currently returns HTTP 404 (checked October 15, 2026). Request an updated download from the ET-BERT maintainers; this repository does not claim to host a working replacement.
- **Input:** arrange the flow PCAPs under one directory per application class.
- **Preprocessing:** if the downloaded captures already represent individual flows, skip session splitting and start with feature extraction.

## ISCX-VPN-Service

This is the six-class service classification task constructed from the ISCX VPN-nonVPN traffic collection. The original collection includes PCAP traffic for multiple services and applications captured with and without VPN.

- **Download:** [official UNB/CIC dataset page](https://www.unb.ca/cic/datasets/vpn.html) → [provider download form](https://cicresearch.ca/CICDataset/ISCX-VPN-NonVPN-2016/). Complete the provider's form and select the PCAP data. The form displayed a server-error notice during the link check; retry through the official page if submission fails.
- **Labels:** organize the selected VPN captures into the six service classes used for this task.
- **Preprocessing:** split each capture into sessions, then extract features.

## ISCX-VPN-App

This is the 14-class application classification task based on the same ISCX collection.

- **Download:** use the same [official ISCXVPN2016 download](https://www.unb.ca/cic/datasets/vpn.html).
- **Labels:** organize captures by application rather than by service.
- **Preprocessing:** split each capture into sessions, then extract features.

The service and application tasks do not require two different raw dataset downloads. Their capture selections and class mappings differ. In particular, the provider's overall traffic categories are not a ready-made mapping for MultiFlow's 14 application labels. Exact MultiFlow label mappings and original sample selections still need to be released.

## USTC-TFC

USTC-TFC2016 contains benign application traffic and malware traffic. MultiFlow uses 20 categories: 10 benign and 10 malware classes.

- **Download:** [dataset repository](https://github.com/davidyslu/USTC-TFC2016).
- **Capture folders:** [Benign](https://github.com/davidyslu/USTC-TFC2016/tree/master/Benign) and [Malware](https://github.com/davidyslu/USTC-TFC2016/tree/master/Malware).
- **Preparation:** unpack the `.7z` captures and create one directory per application or malware class. Do not use only `Benign` and `Malware` as the two labels for this 20-class task.
- **Preprocessing:** split the raw captures into sessions, then extract features.

## Local Data Layout

Keep downloaded and generated data in the ignored `data/` directory, separate from this documentation:

```text
data/
└── USTC-TFC/
    ├── raw/
    │   ├── BitTorrent/
    │   │   └── capture.pcap
    │   └── Cridex/
    │       └── capture.pcap
    ├── flows/      # Output of split_pcap.py
    ├── features/   # Output of extract_features.py
    └── splits/     # train.csv, valid.csv, test.csv
```

Example, from the repository root:

```bash
python3 src/preprocessing/split_pcap.py \
  --input-dir data/USTC-TFC/raw \
  --output-dir data/USTC-TFC/flows \
  --splitcap /path/to/SplitCap.exe

python3 src/data/extract_features.py \
  --pcap-root data/USTC-TFC/flows \
  --output-dir data/USTC-TFC/features

python3 src/preprocessing/split_dataset.py \
  --input data/USTC-TFC/features/all_flows.csv \
  --output-dir data/USTC-TFC/splits
```

See the [main README](../README.md) for installation and training. Follow each provider's access terms, license and citation requirements; dataset files are not redistributed by this repository.
