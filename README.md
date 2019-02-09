# goPortScanner

This is a simple port scanner written in go, supporting concurrent tcp and udp scans.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.
```bash
$ git clone https://github.com/ymerkli/goPortScanner.git
```

### Prerequisites

Have go installed.

### Example output
```bash
$ go run main.go -i 45.33.32.156 -p 1:1000
[2019-02-09 11:56:25] Starting port scanning on 45.33.32.156
Port      State     Transport Protocol  Service             Description
22        Open      tcp                 ssh                 The Secure Shell (SSH) Protocol
80        Open      tcp                 www-http            World Wide Web HTTP
Showed 2 open ports out of 1000 total ports
```

## Authors

* **Yannick Merkli** - [ymerkli](https://github.com/ymerkli)
