# Zyra: eBPF-based Firewall CLI Tool
![Zyra Logo](./assets/logo.svg)

**Zyra** is a lightweight, high-performance Linux firewall built with Rust, eBPF and Aya. It performs policy enforcement in the XDP layer while keeping policy management in userspace.

## Rule Engine

Zyra now uses a structured rule model designed for deterministic policy evaluation:

- **Stable rule ID**: every rule has a unique non-zero identifier.
- **Priority**: lower numbers win; equal priorities are resolved by lower rule ID.
- **Match key**: IPv4 address, port, IP protocol and flow direction.
- **Wildcards**: `0.0.0.0`, port `0`, and protocol `any` represent wildcard fields.
- **Duplicate protection**: identical match keys are rejected by the userspace validator.
- **Kernel enforcement**: the XDP program evaluates a bounded set of exact/wildcard candidates through a BPF hash map instead of scanning the complete rule set.

The policy path is:

```text
CLI
 │
 ▼
RuleEngine ── validate ──► RuleKey + priority + action
 │
 ▼
Pinned BPF RULES map
 │
 ▼
XDP packet parser
 │
 ├── best matching rule ──► ALLOW / BLOCK
 └── no match ─────────────► PASS
```

This keeps the userspace policy API independent from the packet-processing hot path and gives the kernel a bounded lookup cost.

## Installation

### Prerequisites
- Rust stable
- Linux kernel with eBPF/XDP support
- clang, libbpf and bpftool
- Root privileges for attaching XDP programs

### Building
```bash
git clone https://github.com/saugat913/zyra.git
cd zyra
cargo build --release
```

## Usage

### Start
```bash
sudo zyra start eth0
```

### Add rules
Block TCP/80 from one IPv4 address:
```bash
sudo zyra add-rule --id 10 --priority 100 --ip 192.168.1.100 --port 80 --protocol tcp --direction inbound --action block
```

Allow HTTPS traffic from anywhere:
```bash
sudo zyra add-rule --id 20 --priority 200 --port 443 --protocol tcp --direction inbound --action allow
```

Allow any TCP traffic from a trusted host:
```bash
sudo zyra add-rule --id 30 --priority 50 --ip 192.168.1.10 --protocol tcp --direction inbound --action allow
```

`priority` is explicit so policy precedence is not dependent on hash-map iteration order.

### List rules
```bash
sudo zyra list-rules
```

### Monitor events
```bash
sudo zyra listen
```

### Stop
```bash
sudo zyra stop
```

## Architecture

```text
                   USERSPACE
┌───────────────────────────────────────────┐
│ CLI                                       │
│  │                                        │
│  ▼                                        │
│ RuleEngine ──► validation / ordering      │
│  │                                        │
│  ▼                                        │
│ pinned RULES map                          │
└───────────────┬───────────────────────────┘
                │ BPF lookup
                ▼
              KERNEL
┌───────────────────────────────────────────┐
│ XDP                                       │
│  │                                        │
│  ├─ Ethernet / IPv4 / TCP / UDP parsing  │
│  ├─ bounded wildcard candidate lookup     │
│  ├─ priority resolution                   │
│  └─ XDP_PASS / XDP_DROP                  │
└───────────────────────────────────────────┘
                │
                ▼
           EVENTS RingBuf
```

## Development

Run the Rust test suite with:
```bash
cargo test
```

The rule engine has unit tests for validation, duplicate IDs and deterministic priority ordering. Before deployment, verify the generated eBPF program with your target kernel and test the policy using real traffic.

## Project Status

Zyra is actively under development. The current rule engine establishes the foundation for richer policy features such as CIDR matching, source/destination address fields, stateful connections, protocol-specific predicates, rule deletion/update, atomic policy reloads, structured events and benchmarking.

## License

MIT OR Apache-2.0.
