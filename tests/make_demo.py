"""Generate an offline synthetic example, never send packets to a network."""
import argparse
from pathlib import Path
from tests.fixtures import trace, pcap_bytes, pcapng_bytes


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    data = (pcapng_bytes if args.output.suffix == ".pcapng" else pcap_bytes)(trace(close=True))
    with args.output.open("xb") as stream:
        stream.write(data)
    print("Created synthetic offline fixture (not real RF4 traffic):", args.output)


if __name__ == "__main__":
    main()
