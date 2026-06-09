#!/usr/bin/env python3

import argparse
import ipaddress
import json
import os
import socket
import struct


DEFAULT_SOCKET = os.environ.get("BIRD_YI_SOCKET", "/usr/local/var/run/bird_yi.ctl")

COMMANDS = {
    "status": 0,
    "memory": 1,
    "symbols": 2,
    "ospf": 3,
    "protocols": 4,
}


class Break:
    pass


BREAK = Break()


def enc_type(major, value):
    if value < 24:
        return bytes([(major << 5) | value])
    if value <= 0xff:
        return bytes([(major << 5) | 24, value])
    if value <= 0xffff:
        return bytes([(major << 5) | 25]) + value.to_bytes(2, "big")
    if value <= 0xffffffff:
        return bytes([(major << 5) | 26]) + value.to_bytes(4, "big")
    return bytes([(major << 5) | 27]) + value.to_bytes(8, "big")


def cbor_encode(obj):
    if isinstance(obj, int):
        if obj >= 0:
            return enc_type(0, obj)
        return enc_type(1, -obj - 1)
    if isinstance(obj, str):
        raw = obj.encode()
        return enc_type(3, len(raw)) + raw
    if isinstance(obj, bytes):
        return enc_type(2, len(obj)) + obj
    if isinstance(obj, list):
        return enc_type(4, len(obj)) + b"".join(cbor_encode(v) for v in obj)
    if isinstance(obj, dict):
        data = b"".join(cbor_encode(k) + cbor_encode(v) for k, v in obj.items())
        return enc_type(5, len(obj)) + data
    raise TypeError(f"unsupported CBOR value: {obj!r}")


class Decoder:
    def __init__(self, data):
        self.data = data
        self.pt = 0

    def read(self, size):
        if self.pt + size > len(self.data):
            raise ValueError("truncated CBOR response")

        raw = self.data[self.pt:self.pt + size]
        self.pt += size
        return raw

    def read_ai(self, ai):
        if ai < 24:
            return ai
        if ai == 24:
            return self.read(1)[0]
        if ai == 25:
            return int.from_bytes(self.read(2), "big")
        if ai == 26:
            return int.from_bytes(self.read(4), "big")
        if ai == 27:
            return int.from_bytes(self.read(8), "big")
        if ai == 31:
            return None
        raise ValueError(f"unsupported CBOR additional value {ai}")

    def decode(self):
        first = self.read(1)[0]
        if first == 0xff:
            return BREAK

        major = first >> 5
        ai = first & 0x1f
        val = self.read_ai(ai)

        if major == 0:
            return val
        if major == 1:
            return -val - 1
        if major == 2:
            return self.decode_bytes(val)
        if major == 3:
            return self.decode_text(val)
        if major == 4:
            return self.decode_array(val)
        if major == 5:
            return self.decode_map(val)
        if major == 6:
            return self.decode_tag(val)
        if major == 7:
            return self.decode_simple(ai)

        raise ValueError(f"unsupported CBOR major type {major}")

    def decode_bytes(self, length):
        if length is not None:
            return self.read(length)

        chunks = []
        while True:
            chunk = self.decode()
            if chunk is BREAK:
                return b"".join(chunks)
            chunks.append(chunk)

    def decode_text(self, length):
        if length is not None:
            return self.read(length).decode()

        chunks = []
        while True:
            chunk = self.decode()
            if chunk is BREAK:
                return "".join(chunks)
            chunks.append(chunk)

    def decode_array(self, length):
        values = []
        if length is None:
            while True:
                item = self.decode()
                if item is BREAK:
                    return values
                values.append(item)

        for _ in range(length):
            values.append(self.decode())
        return values

    def decode_map(self, length):
        values = {}
        if length is None:
            while True:
                key = self.decode()
                if key is BREAK:
                    return values
                values[map_key(key)] = self.decode()

        for _ in range(length):
            key = self.decode()
            values[map_key(key)] = self.decode()
        return values

    def decode_tag(self, tag):
        value = self.decode()

        if tag == 1:
            return value
        if tag == 4 and isinstance(value, list) and len(value) == 2:
            shift, mantissa = value
            return mantissa * (10 ** shift)
        if tag == 52 and isinstance(value, bytes) and len(value) == 4:
            return str(ipaddress.IPv4Address(value))
        if tag == 54 and isinstance(value, bytes) and len(value) == 16:
            return str(ipaddress.IPv6Address(value))

        return {"tag": tag, "value": normalize(value)}

    def decode_simple(self, ai):
        if ai == 20:
            return False
        if ai == 21:
            return True
        if ai in (22, 23):
            return None
        if ai == 25:
            return struct.unpack(">e", self.read(2))[0]
        if ai == 26:
            return struct.unpack(">f", self.read(4))[0]
        if ai == 27:
            return struct.unpack(">d", self.read(8))[0]
        return {"simple": ai}


def cbor_decode(data):
    return Decoder(data).decode()


def normalize(obj):
    if isinstance(obj, dict):
        return {str(normalize(k)): normalize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [normalize(v) for v in obj]
    if isinstance(obj, tuple):
        return [normalize(v) for v in obj]
    if isinstance(obj, bytes):
        return list(obj)
    return obj


def map_key(obj):
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj

    return json.dumps(normalize(obj), sort_keys=True)


def request(socket_path, command, args, timeout):
    payload = {
        "command:do": {
            "command": COMMANDS[command],
            "args": [{"arg": arg} for arg in args],
        }
    }

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        s.connect(socket_path)

        hello = b""
        while len(hello) < 10:
            hello += s.recv(10 - len(hello))

        s.sendall(cbor_encode(payload))

        chunks = []
        while True:
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break

            if not chunk:
                break
            chunks.append(chunk)

    if not chunks:
        raise RuntimeError("no response from BIRD YI socket")

    return cbor_decode(b"".join(chunks))


def main():
    parser = argparse.ArgumentParser(description="Query BIRD's YANG/CBOR interface")
    parser.add_argument("-s", "--socket", default=DEFAULT_SOCKET, help="YI socket path")
    parser.add_argument("--timeout", type=float, default=1.0, help="socket read timeout")
    parser.add_argument("show", choices=["show"])
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("args", nargs="*")
    ns = parser.parse_args()

    answer = request(ns.socket, ns.command, ns.args, ns.timeout)
    print(json.dumps(normalize(answer), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
