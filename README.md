# DoQlyzer
**DoQlyzer** is a specialized fork of the original [DoHLyzer](https://github.com/ahlashkari/DoHLyzer) tool, engineered to support **DNS over QUIC (DoQ)** traffic analysis. It captures network traffic, extracts statistical and time-series features, and is optimized for generating high-quality datasets for machine learning.

## Key Features & Modifications

### 1. DNS over QUIC (DoQ) Support
*   **Protocol Support**: Modified to parse **UDP port 853** traffic (standard DoQ port) instead of just TCP/443.
*   **QUIC Parsing**: Disabled strict TLS layer checks to allow processing of raw QUIC/UDP packets as valid flows.

### 2. Enhanced Flow Aggregation
We introduced new arguments to give you precise control over how flows are split, which is critical for generating large datasets from limited capture files.

*   **`--max-packets N`**: Splits a long flow into multiple smaller flows, each containing `N` packets.
    *   *Use Case*: Generating 100,000+ samples for Deep Learning from a few long tunneling sessions.
*   **`--duration T`**: Splits flows based on a time duration `T` (in seconds).

### 3. Modern Compatibility
*   **Scapy 2.6+ Support**: Patched `packet_time.py` and `response_time.py` to handle `Decimal` timestamp objects, preventing crashes on modern Python environments.

## Installation

1.  Clone the repository:
    ```bash
    git clone https://github.com/Saurashtr02/doqlyzer.git
    cd doqlyzer
    ```
2.  Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

## Usage

### Basic Feature Extraction
To extract features from a PCAP file containing DoQ traffic:

```bash
python3 meter/doqlyzer.py -f /path/to/capture.pcap -c /path/to/output.csv
```

### Advanced Usage (Dataset Generation)
To generate a robust dataset by splitting flows into 5-packet chunks:

```bash
python3 meter/doqlyzer.py -f capture.pcap -c output.csv --max-packets 5
```

## Original Acknowledgement
This project is based on **DoHLyzer** by the Canadian Institute for Cybersecurity (CIC).
*   **Original Paper**: "Detection of DoH Tunnels using Time-series Classification of Encrypted Traffic", MontazeriShatoori et al. (2020).
*   **Original Repo**: [https://github.com/ahlashkari/DoHLyzer](https://github.com/ahlashkari/DoHLyzer)
