# YANG/CoAP runtime manual

This document describes the experimental BIRD YANG/CoAP runtime available on
the `yang-coap-runtime-v3.3` branch. The runtime exposes a small CLI-oriented
YANG model over CoAP over TCP, with SID/CBOR payloads.

## Scope

Implemented parts:

- CoAP over TCP listener configured from `bird.conf`.
- `/.well-known/core` discovery endpoint.
- `/c` CORECONF-style RPC endpoint using SID/CBOR payloads.
- CLI model RPCs for memory, status, symbols, and protocols.
- Live listener lifecycle on `configure`: create, keep, replace, and delete.
- Parser and runtime tests for configuration, CBOR, CoAP, RPCs, and listener
  reconfiguration.

Current limitations:

- UDP CoAP is rejected by the configuration parser.
- The `restricted` option is parsed and participates in reconfiguration
  matching, but the current CLI model does not yet enforce per-RPC privilege
  reduction. Do not expose this listener to untrusted networks.
- The runtime currently supports only the `cli` model.
- Authentication and transport security are not implemented in this runtime.

## Build

Build BIRD normally:

```sh
make -j4
```

The runtime adds the `lib/cbor.*`, `lib/coap.*`, and `yang/` objects to the
regular build.

## Configuration

Minimal loopback-only example:

```bird
log stderr all;
router id 192.0.2.1;

protocol device {}

yang mgmt {
  model cli;
  restricted yes;
  listen tcp coap {
    local 127.0.0.1;
    port 15683;
  };
}
```

Full syntax:

```bird
yang [NAME] {
  model cli;
  restricted yes|no;
  listen tcp coap {
    local ADDRESS;
    port NUMBER;
  };
}
```

Configuration fields:

| Field | Meaning | Default |
| --- | --- | --- |
| `NAME` | Optional BIRD symbol for the YANG API instance. If omitted, BIRD generates `yang0`, `yang1`, and so on. | generated |
| `model cli` | Selects the CLI-oriented YANG model. This is mandatory. | none |
| `restricted yes|no` | Stores the intended restricted-mode flag for this API instance. | `no` |
| `listen tcp coap` | Enables a CoAP-over-TCP listener. | none |
| `local ADDRESS` | Local address to bind. Use `127.0.0.1` or `::1` for local management only. | `::1` |
| `port NUMBER` | TCP port to bind. | `5683` |

Operational parser behavior:

- Duplicate listeners in one `yang` block are rejected.
- `listen udp coap { ... }` is rejected because UDP runtime support is not
  implemented yet.
- A `yang` block without `model cli` is rejected.

## Starting BIRD

Start BIRD with the config containing the `yang` block:

```sh
./bird -f -c /path/to/bird.conf -s /tmp/bird.ctl -P /tmp/bird.pid
```

The `-Y` UNIX-socket option belongs to the older YI/CBOR interface. It is not
required for the CoAP listener described here; the CoAP listener is controlled
by the `yang { ... }` configuration block.

Reconfiguration is live:

```sh
./birdc -s /tmp/bird.ctl configure
```

If the configured address or port changes, BIRD closes the old listener and
opens the new one during commit.

## Endpoints

Discovery:

```text
GET coap+tcp://HOST:PORT/.well-known/core
```

The response is link-format text and advertises:

```text
</y>;rt="core.c.yl",</c>;rt="core.c.ds",</s>;rt="core.c.ev"
```

CLI model RPC endpoint:

```text
POST coap+tcp://HOST:PORT/c
```

Request payload format:

```text
CBOR map: { RPC_SID: null }
```

Response payload format:

```text
CBOR map: { RPC_OUTPUT_SID: output-map }
```

The current implementation returns these CoAP errors:

| Condition | CoAP response |
| --- | --- |
| Unknown path | `4.04 Not Found` |
| Unsupported method on `/c` | `4.05 Method Not Allowed` |
| Unsupported critical option | `4.02 Bad Option` |
| Bad CBOR or unexpected SID | `4.00 Bad Request` |

## RPCs and SIDs

| RPC | Request SID | Output SID | Output summary |
| --- | ---: | ---: | --- |
| `show memory` | `60001` | `60003` | Memory buckets and page accounting. |
| `show status` | `60025` | `60027` | BIRD version, router ID, hostname, timestamps, config state. |
| `show symbols` | `60036` | `60038` | Config symbols with names and symbol classes. |
| `show protocols` | `60043` | `60045` | Protocol name, protocol type, table, state, state-change time, status text. |

The SID assignment is stored in:

```text
yang/bird@2026-02-10.sid
```

The YANG model is stored in:

```text
yang/bird.yang
```

## Example client

The tested sample client is:

```text
yang/examples/coap_cli_client.py
```

It uses only the Python standard library and speaks CoAP/TCP + CBOR directly.

Query discovery:

```sh
python3 yang/examples/coap_cli_client.py --host 127.0.0.1 --port 15683 well-known
```

Query status:

```sh
python3 yang/examples/coap_cli_client.py --host 127.0.0.1 --port 15683 status
```

Example status output:

```json
{
  "status": {
    "boot_time": 1810000000000000,
    "current_time": 1810000001000000,
    "hostname": "router1",
    "load_time": 1810000000500000,
    "router_id": "192.0.2.1",
    "state": "up",
    "version": "3.3.0"
  }
}
```

Query other RPCs:

```sh
python3 yang/examples/coap_cli_client.py --host 127.0.0.1 --port 15683 memory
python3 yang/examples/coap_cli_client.py --host 127.0.0.1 --port 15683 symbols
python3 yang/examples/coap_cli_client.py --host 127.0.0.1 --port 15683 protocols
```

Print raw numeric SID maps instead of friendly JSON fields:

```sh
python3 yang/examples/coap_cli_client.py --host 127.0.0.1 --port 15683 --raw status
```

## Automated tests

Run targeted tests:

```sh
obj/lib/cbor_test
obj/lib/coap_test
obj/yang/config_test
python3 yang/coap_runtime_test.py
```

`yang/coap_runtime_test.py` starts a real BIRD instance with a temporary
configuration, connects to the CoAP listener, verifies discovery, error
responses, all four RPCs, live listener reconfiguration, and executes the
sample client against the running listener.

Run the normal test suite:

```sh
make tests_run
```
