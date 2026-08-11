"""PCAP file import — process capture files through leetha's fingerprinting pipeline."""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from scapy.all import PcapReader

from leetha.capture.protocols import PARSER_CHAIN

logger = logging.getLogger(__name__)

SUPPORTED_EXTENSIONS = frozenset({".pcap", ".pcapng", ".cap"})
DEFAULT_MAX_SIZE_MB = 500


@dataclass
class ImportProgress:
    """Progress state for a PCAP import."""
    filename: str
    total_packets: int = 0
    processed: int = 0
    errors: int = 0
    done: bool = False


def validate_pcap_file(path: Path, max_size_mb: int = DEFAULT_MAX_SIZE_MB) -> str | None:
    """Validate a PCAP file before import. Returns error message or None if OK."""
    if not path.exists():
        return f"File not found: {path}"
    if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return f"Unsupported format: {path.suffix} (expected {', '.join(SUPPORTED_EXTENSIONS)})"
    size_mb = path.stat().st_size / (1024 * 1024)
    if size_mb > max_size_mb:
        return f"File too large: {size_mb:.1f} MB (max {max_size_mb} MB)"
    return None


def _classify_frame(frame, interface_tag: str):
    """Run a raw scapy frame through the parser chain. Returns CapturedPacket(s) or None."""
    for parser in PARSER_CHAIN:
        try:
            result = parser(frame)
            if result is None:
                continue
            if isinstance(result, list):
                # List-returning parsers (e.g. parse_dns_answer) yield an
                # empty list for traffic they don't recognise. That is a
                # "no match" -- not a result -- so the chain must keep
                # walking, otherwise every parser after it is unreachable.
                if not result:
                    continue
                for pkt in result:
                    pkt.interface = interface_tag
                return result
            result.interface = interface_tag
            return result
        except Exception:
            continue
    return None


async def process_pcap(
    path: Path,
    packet_queue: asyncio.Queue,
    on_progress: Callable[[ImportProgress], None] | None = None,
) -> ImportProgress:
    """Import a PCAP file and push parsed packets onto the processing queue.

    Each packet is run through the PARSER_CHAIN and tagged with
    interface="pcap:<filename>". Successfully parsed packets are
    enqueued for the standard _process_loop() to handle.
    """
    filename = path.name
    interface_tag = f"pcap:{filename}"
    progress = ImportProgress(filename=filename)

    # Count total packets first for progress reporting
    try:
        count = 0
        with PcapReader(str(path)) as reader:
            for _ in reader:
                count += 1
        progress.total_packets = count
    except Exception as e:
        logger.warning("Could not count packets in %s: %s", path, e)
        progress.total_packets = 0

    if on_progress:
        on_progress(progress)

    # Process packets
    try:
        with PcapReader(str(path)) as reader:
            for frame in reader:
                try:
                    result = _classify_frame(frame, interface_tag)
                    if result is None:
                        progress.processed += 1
                        continue

                    packets = result if isinstance(result, list) else [result]
                    for pkt in packets:
                        await packet_queue.put(pkt)

                    progress.processed += 1
                except Exception:
                    progress.errors += 1
                    progress.processed += 1

                if on_progress and progress.processed % 500 == 0:
                    on_progress(progress)
    except Exception as e:
        logger.error("Failed to read PCAP %s: %s", path, e)

    progress.done = True
    if on_progress:
        on_progress(progress)

    return progress
