"""TCP SYN / SYN-ACK fingerprint parser."""
from __future__ import annotations

from leetha.capture.packets import CapturedPacket


def _satori_signature(ip, tcp, options_detailed: list[str]) -> str:
    """Build a Satori-format TCP signature.

    Satori encodes a stack as ``window:ttl:df:iplen:options:quirks`` --
    e.g. ``2048:128:0:48:M16384,N,N,S:.``. Unlike the p0f-style string
    leetha already emits, the option list carries its *values* (``M1460``,
    ``W6``), so it has to be built separately.
    """
    df = 1 if (int(ip.flags) & 0x02) else 0
    opts = ",".join(options_detailed) if options_detailed else "."
    return f"{tcp.window}:{ip.ttl}:{df}:{ip.len}:{opts}:."


def parse_tcp_syn(packet) -> CapturedPacket | None:
    """Extract TCP handshake fingerprint data from a scapy packet.

    Matches SYN (client stack) and SYN-ACK (server stack). The SYN-ACK
    direction is what identifies listening devices -- PLCs, printers,
    NAS boxes -- so both are captured, tagged with ``tcp_flags`` so
    downstream matchers can tell request from response.
    """
    try:
        from scapy.layers.inet import IP, TCP
    except ImportError:
        return None

    if not packet.haslayer(TCP) or not packet.haslayer(IP):
        return None

    tcp = packet[TCP]
    ip = packet[IP]

    # SYN, with or without ACK. Anything else is mid-stream traffic.
    if not (tcp.flags & 0x02):
        return None
    is_synack = bool(tcp.flags & 0x10)

    options = []
    options_detailed = []
    mss = None
    window_scale = None
    for opt_name, opt_val in tcp.options:
        if opt_name == "MSS":
            mss = opt_val
            options.append("M")
            options_detailed.append(f"M{opt_val}")
        elif opt_name == "NOP":
            options.append("N")
            options_detailed.append("N")
        elif opt_name == "WScale":
            window_scale = opt_val
            options.append("W")
            options_detailed.append(f"W{opt_val}")
        elif opt_name == "Timestamp":
            options.append("T")
            options_detailed.append("T")
        elif opt_name == "SAckOK":
            options.append("S")
            options_detailed.append("S")
        elif opt_name == "EOL":
            options.append("E")
            options_detailed.append("E")
        else:
            options.append("?")
            options_detailed.append("?")

    return CapturedPacket(
        protocol="tcp_syn",
        hw_addr=packet.src,
        ip_addr=ip.src,
        target_ip=ip.dst,
        target_hw=packet.dst,
        fields={
            "ttl": ip.ttl,
            "window_size": tcp.window,
            "mss": mss,
            "tcp_options": ",".join(options),
            "window_scale": window_scale,
            "tcp_flags": "SA" if is_synack else "S",
            "df": 1 if (int(ip.flags) & 0x02) else 0,
            "ip_len": ip.len,
            "satori_sig": _satori_signature(ip, tcp, options_detailed),
        },
        raw=bytes(packet) if hasattr(packet, '__bytes__') else None,
    )
