# MultiFlow Source Code Documentation

This directory contains the core source code of the MultiFlow project, used for multimodal representation learning and classification of encrypted network traffic. The project adopts a modular design, divided into three main parts: data processing, preprocessing, and models.

## Directory Structure

```
src/
├── data/                          # Data processing module
│   ├── build_vocab.py            # Build attribute value vocabulary and embedding matrix
│   ├── extract_stats_features.py  # Extract network flow statistical features
│   └── extract_stats_payload.py   # Extract network packet payload features
├── preprocessing/                 # Data preprocessing module
│   └── split_dataset.py           # Network flow splitting and processing
└── models/                        # Model training module
    └── train.py                   # Model training script
```

---

## Module Details

### 1. Data Processing Module (`data/`)

#### `build_vocab.py` - Attribute Value Vocabulary and Embedding Matrix Construction

**Function:**
- Build Word2Vec vocabulary from CSV-formatted network flow attribute data
- Generate embedding vector matrix for attribute values
- Output dictionary and embedding data for subsequent use

**Main Classes:**

```python
class AttributeEmbedding
```

**Core Methods:**
- `__init__()`: Initialize, load corpus, train Word2Vec model, generate embedding matrix
- `load_corpus()`: Load corpus from CSV file, each sequence retains at most 40 packets' attribute values
- `get_vector()`: Query embedding vector for specified token

**Input:**
- CSV file: Contains sequences of network packet attribute values (comma-separated)

**Output:**
- `{prefix}_dict.pkl`: Word2Vec dictionary (token→index mapping)
- `{prefix}_embedding.npy`: Embedding matrix (numpy array format)
- `{prefix}_word2vec.model`: Word2Vec model file

**Configuration Parameters:**
- `embedding_dim`: Embedding dimension (default 300)
- `window`: Word2Vec context window size (default 5)
- `max_packets`: Maximum number of packets extracted per flow (default 40)

---

#### `extract_stats_features.py` - Network Flow Statistical Feature Extraction

**Function:**
- Parse network flows from PCAP files
- Extract statistical features of network flows: packet length, packet direction, inter-arrival time (IAT)
- Batch process multiple PCAP files

**Main Functions:**

| Function Name | Description |
|---------------|-------------|
| `get_flow_features(pcap_path)` | Extract features of a single flow from PCAP file |
| `append_csv(path, rows)` | Batch append row data to CSV file |
| `mark_processed()` | Mark processed PCAP files |
| `get_processed_pcapfile()` | Read log of processed files |

**Extracted Features:**
- **Lengths**: Byte length of each packet (absolute value)
- **Directions**: Packet transmission direction (1 for uplink, -1 for downlink)
- **IATs**: Inter-arrival time intervals (milliseconds × 100, for easier discretization)

**Input:**
- PCAP files (network packet capture files)

**Output:**
- CSV format: Contains flow features of lengths, directions, iats

**Configuration Parameters:**
- `max_packets`: Maximum number of packets extracted per flow (default 40)
- `BATCH_SIZE`: File batch processing size (default 100)
- `NUM_WORKERS`: Number of multiprocess worker threads

---

#### `extract_stats_payload.py` - Network Packet Payload Feature Extraction

**Function:**
- Extract actual payload data of network packets from PCAP files
- Use Bigram features to represent packet content
- Simultaneously extract statistical features (length, direction, IAT)

**Main Functions:**

| Function Name | Description |
|---------------|-------------|
| `get_flow_features(pcap_path)` | Extract complete features of flow (statistics + Payload) |
| `bigram_generation()` | Generate Bigram features for packet data |
| `mark_processed()` | Mark processed files |
| `cut()` | Process data in chunks |

**Extracted Features:**
- **Lengths**: Packet lengths
- **Directions**: Transmission directions
- **IATs**: Inter-packet time intervals
- **Payloads**: Bigram feature sequences of packet content

**Input:**
- PCAP files

**Output:**
- CSV format: label, lengths, directions, iats, payloads

**Configuration Parameters:**
- `max_packets`: Maximum number of packets per flow (default 40)
- `payload_len`: Length of individual packet payload string (default 64 characters)
- `payload_pac`: Number of packets extracted per flow (default 10)
- `MAX_FLOWS_PER_LABEL`: Maximum number of flows per label (default 500)
- `NUM_WORKERS`: Number of threads (default 64)

---

### 2. Preprocessing Module (`preprocessing/`)

#### `split_dataset.py` - Network Flow Splitting and Processing

**Function:**
- Parse and split network TCP connections from PCAP files
- Implement flow-level segmentation, handle multi-connection scenarios
- Generate normalized five-tuple identifiers

**Main Functions:**

| Function Name | Description |
|---------------|-------------|
| `get_normalized_five_tuple(pkt)` | Generate normalized five-tuple (src_ip, src_port, dst_ip, dst_port, protocol) |
| `split_multiple_connections_in_session()` | Split multiple independent TCP connections under the same five-tuple |
| `is_timestamp_interval_gt()` | Check if timestamp interval exceeds threshold |
| `create_folder_if_not_exists()` | Create output directory |
| `split_complete_flows()` | Complete flow splitting main process |

**Key Features:**

1. **Flow Normalization**: 
   - Bidirectional traffic (A→B and B→A) attributed to the same flow
   - Sort IP+Port combinations in lexicographical order

2. **TCP Connection Splitting**:
   - Identify connection start by TCP three-way handshake (pure SYN packets)
   - Identify connection end by FIN/RST packets
   - Filter out invalid connections with fewer than 3 packets

3. **Time Interval Segmentation**:
   - Further split flows based on packet timestamp differences (`time_step` parameter)
   - Avoid mixing data from different time periods in one flow

**Input:**
- PCAP files

**Output:**
- Split PCAP files, stored in specified output directory
- Filename format: `{prefix}-{src_ip}_{src_port}_{dst_ip}_{dst_port}_{protocol}_{flow_count}.pcap`

**Configuration Parameters:**
- `time_step`: Timestamp interval threshold (default 15 seconds)
- `output_dir`: Output directory path

---

### 3. Model Training Module (`models/`)

#### `train.py` - Model Training Script

**Function:**
- Train multimodal network traffic classification model
- Support multiple input features (statistical features, payload features)
- Implement model optimization and performance evaluation

**Expected Functionality:**
- Use previously generated vocabulary and embedding matrix
- Fuse multiple feature modalities (statistical features + payload features)
- Train classifier to distinguish different network applications/protocols

---

## Data Pipeline

```
PCAP files (raw network packets)
    ↓
[preprocessing/split_dataset.py] ← Flow splitting and normalization
    ↓
Split PCAP files
    ↓</content>
<parameter name="filePath">/workspaces/MultiFlow-Robust-Multimodal-Representation-Learning-for-Encrypted-Network-Traffic-Classification/src/README_EN.md
