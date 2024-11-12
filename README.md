# Telnet Sniffer

This is a C++ program that uses Telnet to send commands and `libpcap` to sniff network packets. It’s designed for high-speed packet sniffing and sending commands via Telnet.
Demo: [https://youtu.be/Lwv3TNJIXnU](https://youtu.be/BXXeTuDb_Mg)
## Features

- Connects to a Telnet server and sends commands.
- Sniffs packets on a specified network interface.
- Handles asynchronous packet capturing using `libpcap`.

## Requirements

- C++17
- `libpcap` library
- Network interface access permissions (for packet sniffing)

## Compilation Instructions

### Linux

1. **Install libpcap** (if not already installed):
    ```bash
    sudo apt-get update
    sudo apt-get install libpcap-dev
    ```

2. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/telnet_sniffer.git
    cd telnet_sniffer
    ```

3. **Compile the Program**:
    ```bash
    mkdir -p dist
    g++ main.cpp -std=c++17 -o dist/telnet_sniffer -lpcap
    ```

4. **Run the Program**:
    ```bash
    sudo ./dist/telnet_sniffer
    ```

### macOS

1. **Install libpcap (if needed)**:
    macOS usually comes with `libpcap` pre-installed. If needed, you can install it with Homebrew:
    ```bash
    brew install libpcap
    ```

2. **Clone the Repository**:
    ```bash
    git clone https://github.com/yourusername/telnet_sniffer.git
    cd telnet_sniffer
    ```

3. **Compile the Program**:
    ```bash
    mkdir -p dist
    g++ main.cpp -std=c++17 -o dist/telnet_sniffer -lpcap
    ```

4. **Run the Program**:
    ```bash
    sudo ./dist/telnet_sniffer
    ```

## Usage

When you run the program, you’ll be able to:
- Enter Telnet commands that will be sent to the specified server.
- See captured packet details in the terminal when packets are sniffed on the specified interface.

## Notes

- **Root Permissions**: You may need root privileges to access network interfaces for packet sniffing. Run the program with `sudo` if required.
- **Network Permissions on macOS**: Ensure your terminal application has network access permissions under `System Preferences > Security & Privacy > Privacy`.
