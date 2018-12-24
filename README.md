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
$ go run main.go -i 45.33.32.156 -p 1:30 -t udp
[2018-12-24 13:33:15] Starting port scanning on 45.33.32.156
Port      State     Transport Protocol  Service             Description
13        Open      udp                 daytime             Daytime
12        Open      udp                                     Unassigned
1         Open      udp                 tcpmux              TCP Port Service Multiplexer
23        Open      udp                 telnet              Telnet
24        Open      udp                                     any private mail system
2         Open      udp                 compressnet         Management Utility
22        Open      udp                 ssh                 The Secure Shell (SSH) Protocol
3         Open      udp                 compressnet         Compression Process
25        Open      udp                 smtp                Simple Mail Transfer
14        Open      udp                                     Unassigned
26        Open      udp                                     Unassigned
4         Open      udp                                     Unassigned
15        Open      udp                                     Unassigned
5         Open      udp                 rje                 Remote Job Entry
27        Open      udp                 nsw-fe              NSW User System FE
16        Open      udp                                     Unassigned
6         Open      udp                                     Unassigned
28        Open      udp                                     Unassigned
29        Open      udp                 msg-icp             MSG ICP
7         Open      udp                 echo                Echo
30        Open      udp                                     Unassigned
8         Open      udp                                     Unassigned
19        Open      udp                 chargen             Character Generator
11        Open      udp                 systat              Active Users
10        Open      udp                                     Unassigned
18        Open      udp                 msp                 Message Send Protocol (historic)
9         Open      udp                 discard             Discard
20        Open      udp                 ftp-data            File Transfer [Default Data]
17        Open      udp                 qotd                Quote of the Day
21        Open      udp                 ftp                 File Transfer Protocol [Control]
Showed 30 open ports out of 30 total ports
```

## Authors

* **Yannick Merkli** - [ymerkli](https://github.com/ymerkli)
