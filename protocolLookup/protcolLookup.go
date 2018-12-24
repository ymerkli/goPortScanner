package protocolLookup

import (
	"bufio"
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"strconv"
)

type protocol struct {
	Service        string
	Port           int64
	TransportProto string
	Desc           string
}

var udpProtocols map[int64]protocol
var tcpProtocols map[int64]protocol

// ParsePortsCSV parses the included CSV files and fills in the udp & tcpProtocols maps
func ParsePortsCSV() error {
	udpProtocols = make(map[int64]protocol)
	tcpProtocols = make(map[int64]protocol)

	csvFile, err := os.Open("protocolLookup/service-names-port-numbers.csv")
	if err != nil {
		return fmt.Errorf("Could not open CSV file: %v", err)
	}
	reader := csv.NewReader(bufio.NewReader(csvFile))
	for {
		line, err := reader.Read()
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("Could not read CSV file line: %v", err)
		}
		portStr := line[1]
		port, err := strconv.ParseInt(portStr, 10, 0)
		if err != nil {
			continue
		}
		transportProto := line[2]
		switch transportProto {
		case "udp":
			udpProtocols[port] = protocol{
				Service:        line[0],
				Port:           port,
				TransportProto: "udp",
				Desc:           line[3],
			}
		case "tcp":
			tcpProtocols[port] = protocol{
				Service:        line[0],
				Port:           port,
				TransportProto: "tcp",
				Desc:           line[3],
			}
		default:
			continue
		}
	}
	return nil
}

// GetProtocolInfo returns a pointer to a protocol struct for the respective port and transport protocol
func GetProtocolInfo(port int64, transportProto string) (*protocol, error) {
	switch transportProto {
	case "udp":
		if protocolInfo, ok := udpProtocols[port]; ok {
			return &protocolInfo, nil
		}
		return nil, fmt.Errorf("No udp protcol entry for port %d", port)
	case "tcp":
		if protocolInfo, ok := tcpProtocols[port]; ok {
			return &protocolInfo, nil
		}
		return nil, fmt.Errorf("No tcp protocol entry for port %d", port)
	default:
		return nil, fmt.Errorf("Invalid transport protocol %s", transportProto)
	}
}
