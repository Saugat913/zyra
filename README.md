# Zyra: eBPF-based Firewall CLI Tool
![Zyra Logo](./assets/logo.svg)

**Zyra** is a lightweight, high-performance firewall CLI tool built using [eBPF](https://ebpf.io/) and the [Aya](https://aya-rs.dev/) Rust framework. It leverages the power of eBPF to provide low-latency packet filtering and monitoring directly in the Linux kernel's XDP (eXpress Data Path) layer. Zyra allows users to define firewall rules, monitor network events, and manage network traffic with ease, all from a simple command-line interface.

⚠️ **Note**: Zyra is actively under development. Features and APIs may change as the project evolves. Contributions and feedback are welcome!

## Features

- **Rule-based Packet Filtering**: Add rules to allow or block traffic based on IP address, port, and flow direction (ingress/egress).
- **Real-time Event Monitoring**: Capture and log network events (e.g., packet metadata) sent from the eBPF program to userspace.
- **High Performance**: Utilizes XDP for line-rate packet processing in the kernel.
- **Simple CLI Interface**: Built with `clap` for an intuitive command-line experience.
- **Extensible Architecture**: Modular design with support for adding advanced packet parsing and analysis (e.g., TCP, UDP, DNS, HTTP).
- **Rust Safety**: Leverages Rust's memory safety and the Aya framework for robust eBPF integration.

## Installation

### Prerequisites
- **Rust**: Install the latest stable version via [rustup](https://rustup.rs/).
- **Linux Kernel**: A recent Linux kernel (5.3+) with eBPF and XDP support enabled.
- **Dependencies**:
  - `libbpf` and `bpftool` for eBPF program loading.
  - `clang` for compiling eBPF programs.
  - Install dependencies on Ubuntu/Debian:
    ```bash
    sudo apt update
    sudo apt install -y clang libbpf-dev linux-tools-common linux-tools-$(uname -r)
    ```
- **Root Privileges**: Zyra requires root permissions to attach eBPF programs to network interfaces.

### Building Zyra
1. Clone the repository:
   ```bash
   git clone https://github.com/saugat913/zyra.git
   cd zyra
   ```
2. Build the project:
   ```bash
   cargo build --release
   ```
3. (Optional) Install the binary:
   ```bash
   sudo cp target/release/zyra /usr/local/bin/
   ```

## Usage

Zyra provides a CLI interface to manage the firewall and monitor events. Below are the available commands:

### Start the Firewall
Attach the eBPF program to a network interface:
```bash
sudo zyra start --interface eth0
```
Replace `eth0` with your network interface.

### Stop the Firewall
Detach the eBPF program:
```bash
sudo zyra stop
```

### Add a Firewall Rule
Add a rule to allow or block traffic:
```bash
sudo zyra add-rule --ip 192.168.1.100 --port 80 --direction inbound --action allow
```
- `--ip`: Target IP address (in decimal, e.g., `3232235876` for `192.168.1.100`).
- `--port`: Target port (default: `0` for any).
- `--direction`: `INBOUND` (ingress) or `OUTBOUND` (egress, default: `INBOUND`).
- `--action`: `Allow` or `Block` (default: `Block`).

### List Firewall Rules
Display all active rules:
```bash
sudo zyra list-rules
```

### Listen to Events
Monitor real-time network events from the eBPF program:
```bash
sudo zyra listen
```

### Example Workflow
1. Start the firewall on interface `eth0`:
   ```bash
   sudo zyra start --interface eth0
   ```
2. Add a rule to block HTTP traffic (port 80) from `192.168.1.100`:
   ```bash
   sudo zyra add-rule --ip 3232235876 --port 80 --direction inbound --action block
   ```
3. List rules to verify:
   ```bash
   sudo zyra list-rules
   ```
4. Monitor events:
   ```bash
   sudo zyra listen
   ```
5. Stop the firewall:
   ```bash
   sudo zyra stop
   ```

## Project Status
Zyra is **actively under development**. Current features include basic rule-based filtering and event logging. Planned enhancements include:
- Advanced application-layer protocol parsing (e.g., DNS, HTTP).
- Support for more complex rule conditions (e.g., CIDR ranges, protocol-specific filters).
- Improved event logging with structured output formats (e.g., JSON).
- Comprehensive documentation and testing suite.

Check the [Issues](https://github.com/<your-username>/zyra/issues) page for ongoing work and known bugs.

## Development Setup
To contribute to Zyra:
1. Install prerequisites (see [Installation](#installation)).
2. Install additional development tools:
   ```bash
   cargo install cargo-generate
   ```
3. Build and test:
   ```bash
   cargo build
   cargo test
   ```
4. Use `bpftool` to inspect eBPF programs:
   ```bash
   sudo bpftool prog list
   ```

### Running Tests
Zyra includes unit tests for the CLI and firewall logic. Run them with:
```bash
cargo test
```

### Debugging
- Enable verbose logging with `env_logger`:
  ```bash
  RUST_LOG=debug sudo zyra start --interface eth0
  ```
- Inspect eBPF maps with `bpftool`:
  ```bash
  sudo bpftool map dump name EVENTS
  ```

## Contributing
We welcome contributions! To get started:
1. Fork the repository.
2. Create a feature branch (`git checkout -b feature/my-feature`).
3. Commit changes (`git commit -m "Add my feature"`).
4. Push to your fork (`git push origin feature/my-feature`).
5. Open a pull request.

Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) and ensure your code passes `cargo fmt` and `cargo clippy`.

## License
Zyra is licensed under the [MIT License](LICENSE).

## Acknowledgments
- Built with [Aya](https://aya-rs.dev/) for eBPF in Rust.
- Uses [clap](https://crates.io/crates/clap) for CLI parsing.
- Inspired by the eBPF community's efforts to bring programmable networking to Linux.

For questions or feedback, open an issue or contact the maintainers at [your-email@example.com].

