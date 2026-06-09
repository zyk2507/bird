#!/usr/bin/env python3

import argparse
import json
import socket
import struct
import sys


COAP_SCO_CSM = 0xE1
COAP_REQ_GET = 0x01
COAP_REQ_POST = 0x02
COAP_RESP_CONTENT = 0x45

COAP_OPT_URI_PATH = 11

SID_SHOW_MEMORY = 60001
SID_SHOW_MEMORY_OUTPUT = 60003
SID_SHOW_STATUS = 60025
SID_SHOW_STATUS_OUTPUT = 60027
SID_SHOW_SYMBOLS = 60036
SID_SHOW_SYMBOLS_OUTPUT = 60038
SID_SHOW_PROTOCOLS = 60043
SID_SHOW_PROTOCOLS_OUTPUT = 60045

MEMORY_SECTION_NAMES = {
    1: "route_attributes",
    4: "configuration",
    7: "pages",
    12: "protocols",
    15: "routing_tables",
    18: "total",
}

MEMORY_FIELD_NAMES = {
    1: "effective",
    2: "overhead",
    3: "hot",
    4: "alloc_locking_in_rcu",
}


def cbor_uint(value):
    if value < 24:
        return bytes([value])
    if value < 0x100:
        return bytes([0x18, value])
    if value < 0x10000:
        return b"\x19" + struct.pack("!H", value)
    if value < 0x100000000:
        return b"\x1a" + struct.pack("!I", value)
    return b"\x1b" + struct.pack("!Q", value)


def cbor_rpc_call(sid):
    return b"\xa1" + cbor_uint(sid) + b"\xf6"


def coap_option(option_type, previous_type, value):
    delta = option_type - previous_type
    length = len(value)

    if delta < 13:
        delta_head = delta
        delta_ext = b""
    elif delta < 269:
        delta_head = 13
        delta_ext = bytes([delta - 13])
    else:
        delta_head = 14
        delta_ext = struct.pack("!H", delta - 269)

    if length < 13:
        len_head = length
        len_ext = b""
    elif length < 269:
        len_head = 13
        len_ext = bytes([length - 13])
    else:
        len_head = 14
        len_ext = struct.pack("!H", length - 269)

    return bytes([(delta_head << 4) | len_head]) + delta_ext + len_ext + value


def coap_uri_path(*parts):
    previous = 0
    out = b""
    for part in parts:
        value = part.encode("ascii")
        out += coap_option(COAP_OPT_URI_PATH, previous, value)
        previous = COAP_OPT_URI_PATH
    return out


def coap_tcp_frame(code, options=b"", payload=b""):
    body = options
    if payload:
        body += b"\xff" + payload

    length = len(body)
    if length < 13:
        head = bytes([length << 4])
    elif length < 269:
        head = bytes([(13 << 4), length - 13])
    elif length < 65805:
        head = bytes([(14 << 4)]) + struct.pack("!H", length - 269)
    else:
        head = bytes([(15 << 4)]) + struct.pack("!I", length - 65805)

    return head + bytes([code]) + body


def recv_exact(sock, size):
    chunks = []
    while size:
        chunk = sock.recv(size)
        if not chunk:
            raise RuntimeError("connection closed")
        chunks.append(chunk)
        size -= len(chunk)
    return b"".join(chunks)


def recv_frame(sock):
    first = recv_exact(sock, 1)[0]
    length_nibble = first >> 4
    token_len = first & 0x0F

    if length_nibble < 13:
        length = length_nibble
    elif length_nibble == 13:
        length = recv_exact(sock, 1)[0] + 13
    elif length_nibble == 14:
        length = struct.unpack("!H", recv_exact(sock, 2))[0] + 269
    else:
        length = struct.unpack("!I", recv_exact(sock, 4))[0] + 65805

    code = recv_exact(sock, 1)[0]
    token = recv_exact(sock, token_len)
    rest = recv_exact(sock, length)
    return code, token, rest


def response_payload(rest):
    pos = 0
    while pos < len(rest):
        if rest[pos] == 0xFF:
            return rest[pos + 1:]

        byte = rest[pos]
        pos += 1
        delta = byte >> 4
        length = byte & 0x0F

        if delta == 13:
            pos += 1
        elif delta == 14:
            pos += 2
        elif delta == 15:
            raise RuntimeError("invalid CoAP option delta")

        if length == 13:
            length = rest[pos] + 13
            pos += 1
        elif length == 14:
            length = struct.unpack("!H", rest[pos:pos + 2])[0] + 269
            pos += 2
        elif length == 15:
            raise RuntimeError("invalid CoAP option length")

        pos += length

    return b""


class CborReader:
    def __init__(self, data):
        self.data = data
        self.pos = 0

    def read(self, size):
        if self.pos + size > len(self.data):
            raise RuntimeError("truncated CBOR")
        out = self.data[self.pos:self.pos + size]
        self.pos += size
        return out

    def read_len(self, addl):
        if addl < 24:
            return addl
        if addl == 24:
            return self.read(1)[0]
        if addl == 25:
            return struct.unpack("!H", self.read(2))[0]
        if addl == 26:
            return struct.unpack("!I", self.read(4))[0]
        if addl == 27:
            return struct.unpack("!Q", self.read(8))[0]
        raise RuntimeError("unsupported CBOR additional value")

    def item(self):
        first = self.read(1)[0]
        major = first >> 5
        addl = first & 0x1F

        if major == 0:
            return self.read_len(addl)
        if major == 1:
            return -1 - self.read_len(addl)
        if major == 3:
            length = self.read_len(addl)
            return self.read(length).decode("utf-8")
        if major == 4:
            return [self.item() for _ in range(self.read_len(addl))]
        if major == 5:
            return {self.item(): self.item() for _ in range(self.read_len(addl))}
        if major == 7 and addl == 22:
            return None

        raise RuntimeError(f"unsupported CBOR item major={major} addl={addl}")


def decode_cbor(data):
    reader = CborReader(data)
    value = reader.item()
    if reader.pos != len(data):
        raise RuntimeError("trailing CBOR data")
    return value


def coap_code_string(code):
    return f"{code >> 5}.{code & 0x1f:02d}"


def request(sock, code, path, payload=b""):
    sock.sendall(coap_tcp_frame(code, coap_uri_path(*path), payload))

    while True:
        code, _token, rest = recv_frame(sock)
        if code == COAP_SCO_CSM:
            continue
        payload = response_payload(rest)
        if code == COAP_RESP_CONTENT:
            return payload
        text = payload.decode("utf-8", errors="replace")
        raise RuntimeError(f"CoAP {coap_code_string(code)} response: {text}")


def query_well_known(sock):
    payload = request(sock, COAP_REQ_GET, (".well-known", "core"))
    return {"well_known": payload.decode("ascii")}


def query_rpc(sock, sid):
    payload = request(sock, COAP_REQ_POST, ("c",), cbor_rpc_call(sid))
    return decode_cbor(payload)


def rename_map(data, names):
    return {names.get(key, str(key)): value for key, value in data.items()}


def format_memory(raw):
    memory = raw[SID_SHOW_MEMORY_OUTPUT][1]
    return {
        "memory": {
            MEMORY_SECTION_NAMES.get(section, str(section)): rename_map(values, MEMORY_FIELD_NAMES)
            for section, values in memory.items()
        }
    }


def format_status(raw):
    status = raw[SID_SHOW_STATUS_OUTPUT][1]
    return {
        "status": {
            "version": status.get(1),
            "router_id": status.get(2),
            "hostname": status.get(3),
            "current_time": status.get(4),
            "boot_time": status.get(5),
            "load_time": status.get(6),
            "state": status.get(7),
        }
    }


def format_symbols(raw):
    symbols = raw[SID_SHOW_SYMBOLS_OUTPUT][1]
    return {
        "symbols": [
            {
                "name": item.get(1),
                "type": item.get(2),
            }
            for item in symbols
        ]
    }


def format_protocols(raw):
    protocols = raw[SID_SHOW_PROTOCOLS_OUTPUT][1]
    return {
        "protocols": [
            {
                "name": item.get(1),
                "protocol": item.get(2),
                "table": item.get(3),
                "state": item.get(4),
                "since": item.get(5),
                "info": item.get(6),
            }
            for item in protocols
        ]
    }


COMMANDS = {
    "memory": (SID_SHOW_MEMORY, format_memory),
    "status": (SID_SHOW_STATUS, format_status),
    "symbols": (SID_SHOW_SYMBOLS, format_symbols),
    "protocols": (SID_SHOW_PROTOCOLS, format_protocols),
}


def parse_args(argv):
    parser = argparse.ArgumentParser(
        description="Query BIRD's experimental YANG/CoAP CLI model endpoint."
    )
    parser.add_argument("command", choices=["well-known", *COMMANDS.keys()])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default=5683, type=int)
    parser.add_argument("--timeout", default=5.0, type=float)
    parser.add_argument("--raw", action="store_true", help="print numeric SID maps without friendly field names")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv or sys.argv[1:])

    with socket.create_connection((args.host, args.port), timeout=args.timeout) as sock:
        sock.settimeout(args.timeout)
        sock.sendall(coap_tcp_frame(COAP_SCO_CSM))

        if args.command == "well-known":
            out = query_well_known(sock)
        else:
            sid, formatter = COMMANDS[args.command]
            raw = query_rpc(sock, sid)
            out = raw if args.raw else formatter(raw)

    print(json.dumps(out, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
