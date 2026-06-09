#!/usr/bin/env python3

import json
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


COAP_SCO_CSM = 0xE1
COAP_REQ_GET = 0x01
COAP_REQ_POST = 0x02
COAP_RESP_CONTENT = 0x45
COAP_CERR_NOT_FOUND = 0x84
COAP_CERR_METHOD_NOT_ALLOWED = 0x85

COAP_OPT_URI_PATH = 11
COAP_OPT_CONTENT_FORMAT = 12

SID_SHOW_MEMORY = 60001
SID_SHOW_MEMORY_OUTPUT = 60003
SID_SHOW_STATUS = 60025
SID_SHOW_STATUS_OUTPUT = 60027
SID_SHOW_SYMBOLS = 60036
SID_SHOW_SYMBOLS_OUTPUT = 60038
SID_SHOW_PROTOCOLS = 60043
SID_SHOW_PROTOCOLS_OUTPUT = 60045


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
        d = delta
        de = b""
    elif delta < 269:
        d = 13
        de = bytes([delta - 13])
    else:
        d = 14
        de = struct.pack("!H", delta - 269)

    if length < 13:
        l = length
        le = b""
    elif length < 269:
        l = 13
        le = bytes([length - 13])
    else:
        l = 14
        le = struct.pack("!H", length - 269)

    return bytes([(d << 4) | l]) + de + le + value


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


def coap_uri_path(*parts):
    previous = 0
    out = b""
    for part in parts:
        value = part.encode("ascii")
        out += coap_option(COAP_OPT_URI_PATH, previous, value)
        previous = COAP_OPT_URI_PATH
    return out


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
    ln = first >> 4
    toklen = first & 0x0F

    if ln < 13:
        length = ln
    elif ln == 13:
        length = recv_exact(sock, 1)[0] + 13
    elif ln == 14:
        length = struct.unpack("!H", recv_exact(sock, 2))[0] + 269
    else:
        length = struct.unpack("!I", recv_exact(sock, 4))[0] + 65805

    code = recv_exact(sock, 1)[0]
    token = recv_exact(sock, toklen)
    rest = recv_exact(sock, length)
    return code, token, rest


def response_payload(rest):
    pos = 0
    previous = 0
    while pos < len(rest):
        if rest[pos] == 0xFF:
            return rest[pos + 1:]

        byte = rest[pos]
        pos += 1
        delta = byte >> 4
        length = byte & 0x0F

        if delta == 13:
            delta = rest[pos] + 13
            pos += 1
        elif delta == 14:
            delta = struct.unpack("!H", rest[pos:pos + 2])[0] + 269
            pos += 2

        if length == 13:
            length = rest[pos] + 13
            pos += 1
        elif length == 14:
            length = struct.unpack("!H", rest[pos:pos + 2])[0] + 269
            pos += 2

        previous += delta
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


def query_well_known(sock):
    sock.sendall(coap_tcp_frame(COAP_REQ_GET, coap_uri_path(".well-known", "core")))

    while True:
        code, _token, rest = recv_frame(sock)
        if code == COAP_RESP_CONTENT:
            payload = response_payload(rest).decode("ascii")
            assert "</c>" in payload
            assert "</y>" in payload
            return


def query_error(sock, frame, expected_code, expected_text):
    sock.sendall(frame)

    while True:
        code, _token, rest = recv_frame(sock)
        if code == expected_code:
            payload = response_payload(rest).decode("ascii")
            assert expected_text in payload, payload
            return


def query_not_found(sock):
    query_error(
        sock,
        coap_tcp_frame(COAP_REQ_GET, coap_uri_path("missing")),
        COAP_CERR_NOT_FOUND,
        "Not Found",
    )


def query_method_not_allowed(sock):
    query_error(
        sock,
        coap_tcp_frame(COAP_REQ_GET, coap_uri_path("c")),
        COAP_CERR_METHOD_NOT_ALLOWED,
        "POST",
    )


def query_rpc(sock, sid, output_sid):
    sock.sendall(coap_tcp_frame(COAP_REQ_POST, coap_uri_path("c"), cbor_rpc_call(sid)))

    while True:
        code, _token, rest = recv_frame(sock)
        if code == COAP_RESP_CONTENT:
            payload = decode_cbor(response_payload(rest))
            assert output_sid in payload, payload
            return payload[output_sid]


def run_sample_client(repo, port):
    script = repo / "yang" / "examples" / "coap_cli_client.py"
    commands = ("well-known", "memory", "status", "symbols", "protocols")

    for command in commands:
        result = subprocess.run(
            [sys.executable, str(script), "--host", "127.0.0.1", "--port", str(port), command],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if result.returncode:
            raise RuntimeError(result.stdout)

        output = json.loads(result.stdout)
        if command == "well-known":
            assert "</c>" in output["well_known"], output
        else:
            assert command in output, output


def free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def wait_for_port(port, proc):
    deadline = time.time() + 10
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("bird exited before opening YANG listener")
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
            return sock
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("timed out waiting for YANG listener")


def wait_for_port_closed(port):
    deadline = time.time() + 5
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                pass
        except OSError:
            return
        time.sleep(0.05)
    raise RuntimeError("timed out waiting for old YANG listener to close")


def config_body(port, include_yang=True):
    body = (
        "log stderr all;\n"
        "router id 192.0.2.1;\n"
        "protocol device pdev {}\n"
    )

    if include_yang:
        body += (
            "yang mgmt {\n"
            "  model cli;\n"
            "  restricted yes;\n"
            "  listen tcp coap {\n"
            "    local 127.0.0.1;\n"
            f"    port {port};\n"
            "  };\n"
            "}\n"
        )

    return body


def main():
    repo = Path(__file__).resolve().parents[1]
    port = free_port()

    with tempfile.TemporaryDirectory(prefix="bird-yang-coap-") as tmp:
        tmp_path = Path(tmp)
        cfg = tmp_path / "bird.conf"
        ctl = tmp_path / "bird.ctl"
        yi_ctl = tmp_path / "bird-yang.ctl"
        pid = tmp_path / "bird.pid"

        cfg.write_text(config_body(port, "no-yang" not in sys.argv[1:]), encoding="ascii")

        proc = subprocess.Popen(
            [str(repo / "bird"), "-f", "-c", str(cfg), "-s", str(ctl), "-Y", str(yi_ctl), "-P", str(pid)],
            cwd=repo,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )

        try:
            if sys.argv[1:] in (["no-connect"], ["no-yang"]):
                time.sleep(0.5)
                return

            with wait_for_port(port, proc) as sock:
                sock.settimeout(5)
                sock.sendall(coap_tcp_frame(COAP_SCO_CSM))

                tests = sys.argv[1:] or [
                    "well-known",
                    "not-found",
                    "method-not-allowed",
                    "memory",
                    "status",
                    "symbols",
                    "protocols",
                    "sample-client",
                    "reconfigure",
                ]

                if "well-known" in tests:
                    query_well_known(sock)

                if "not-found" in tests:
                    query_not_found(sock)

                if "method-not-allowed" in tests:
                    query_method_not_allowed(sock)

                if "memory" in tests:
                    memory = query_rpc(sock, SID_SHOW_MEMORY, SID_SHOW_MEMORY_OUTPUT)
                    assert 1 in memory

                if "status" in tests:
                    status = query_rpc(sock, SID_SHOW_STATUS, SID_SHOW_STATUS_OUTPUT)
                    assert status[1][1]
                    assert status[1][7] == "up"

                if "symbols" in tests:
                    symbols = query_rpc(sock, SID_SHOW_SYMBOLS, SID_SHOW_SYMBOLS_OUTPUT)
                    symbol_names = {entry[1] for entry in symbols[1]}
                    assert "mgmt" in symbol_names

                if "protocols" in tests:
                    protocols = query_rpc(sock, SID_SHOW_PROTOCOLS, SID_SHOW_PROTOCOLS_OUTPUT)
                    proto_names = {entry[1] for entry in protocols[1]}
                    assert "pdev" in proto_names

                if "sample-client" in tests:
                    run_sample_client(repo, port)

                if "reconfigure" in tests:
                    sock.close()
                    old_port = port
                    port = free_port()
                    cfg.write_text(config_body(port), encoding="ascii")

                    result = subprocess.run(
                        [str(repo / "birdc"), "-s", str(ctl), "configure"],
                        cwd=repo,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        text=True,
                    )
                    if result.returncode:
                        raise RuntimeError(result.stdout)

                    wait_for_port_closed(old_port)
                    with wait_for_port(port, proc) as sock2:
                        sock2.settimeout(5)
                        sock2.sendall(coap_tcp_frame(COAP_SCO_CSM))
                        status = query_rpc(sock2, SID_SHOW_STATUS, SID_SHOW_STATUS_OUTPUT)
                        assert status[1][7] == "up"

        finally:
            proc.terminate()
            try:
                output, _ = proc.communicate(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                output, _ = proc.communicate(timeout=5)

            if proc.returncode not in (0, -15):
                sys.stderr.write(output)
                raise RuntimeError(f"bird exited with {proc.returncode}")


if __name__ == "__main__":
    main()
