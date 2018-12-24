package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ymerkli/goPortScanner/protocolLookup"
)

var (
	maxWorkers = 50
)

type scanPortRes struct {
	Port    int64
	Success bool
	Err     error
}

type scanRes struct {
	scanResults     []scanPortRes
	numPortsScanned int
}

func main() {
	var (
		scanIPStr  string
		portRanges string
	)

	flag.StringVar(&scanIPStr, "i", "", "IP in IPv4 or IPv6 format")
	flag.StringVar(&portRanges, "p", "", "Port range to scan. Format: 1:10,15,20:30")
	flag.Parse()

	scanIP := net.ParseIP(scanIPStr)
	if scanIP == nil {
		fmt.Println(fmt.Errorf("Cannot parse IP %s", scanIPStr))
		return
	}

	portArr, err := parsePorts(portRanges)
	if err != nil {
		fmt.Println(err)
		return
	}

	err = protocolLookup.ParsePortsCSV()
	if err != nil {
		fmt.Println(err)
		return
	}

	scanResult := scanPorts(scanIP, portArr)
	resultString := printScanResults(scanResult)

	fmt.Println(resultString)
	return
}

// Scans all ports given in portArr at the given IP
func scanPorts(scanIP net.IP, portArr []int64) *[]scanPortRes {
	numWorkers := 0
	numPortsToScan := len(portArr)
	doneCh := make(chan bool, 50)
	result := scanRes{}
	result.numPortsScanned = 0
	resultLock := &sync.Mutex{}

	for _, port := range portArr {
		if numWorkers < maxWorkers {
			go scanWorker(scanIP, port, doneCh, &result, resultLock)
			numWorkers++
		} else {
			<-doneCh
			numWorkers--
			go scanWorker(scanIP, port, doneCh, &result, resultLock)
			numWorkers++
		}
	}
	for result.numPortsScanned < numPortsToScan {
		time.Sleep(1 * time.Second)
	}
	return &result.scanResults
}

// scanWorker tries to dial scanIP on the given port and then writes the result to the scanResults map
func scanWorker(scanIP net.IP, port int64, doneCh chan bool, result *scanRes, resultLock *sync.Mutex) {
	address := fmt.Sprintf("%s:%d", scanIP.String(), port)
	_, err := net.DialTimeout("tcp", address, 5*time.Second)
	//defer conn.Close()

	success := (err == nil)
	scanPortRes := scanPortRes{
		Port:    port,
		Success: success,
		Err:     err,
	}
	// aquire Mutex and write to map
	resultLock.Lock()
	result.scanResults = append(result.scanResults, scanPortRes)
	result.numPortsScanned++
	resultLock.Unlock()

	return
}

func printScanResults(scanResults *[]scanPortRes) string {
	numScans := len(*scanResults)
	numOpenPorts := 0
	resString := fmt.Sprintf("%-10s%-10s%-20s%-20s%-30s\n", "Port", "State", "Transport Protocol", "Service", "Description")
	for _, scanPortRes := range *scanResults {
		if !scanPortRes.Success {
			continue
		}
		numOpenPorts++
		// ToDo: implement tcp and udp functionality (flag to set)
		protocol, err := protocolLookup.GetProtocolInfo(scanPortRes.Port, "tcp")
		if err != nil {
			resLine := fmt.Sprintf("%-10d%-10s%-20s%-20s%-30s\n", scanPortRes.Port, "Open", "Unknown", "Unknown", "Unknown")
			resString = fmt.Sprintf("%s%s", resString, resLine)
			continue
		}
		resLine := fmt.Sprintf("%-10d%-10s%-20s%-20s%-30s\n", scanPortRes.Port, "Open", protocol.TransportProto, protocol.Service, protocol.Desc)
		resString = fmt.Sprintf("%s%s", resString, resLine)
	}
	resString = fmt.Sprintf("%s%s", resString, fmt.Sprintf("Showed %d open ports out of %d total ports", numOpenPorts, numScans))

	return resString
}

// Parses a string in the format of 1:10,15,20:30 into an array of integers
// Port ranges are unfolded and put into the result array
func parsePorts(portRanges string) ([]int64, error) {
	var res []int64
	rangesArr := strings.Split(portRanges, ",")
	for _, portRange := range rangesArr {
		portArr := strings.Split(portRange, ":")
		switch len(portArr) {
		case 1:
			port, err := strconv.ParseInt(portArr[0], 10, 0)
			if err != nil {
				return res, fmt.Errorf("Invalid port %s", portRange)
			}
			res = append(res, port)
		case 2:
			lowPort, err := strconv.ParseInt(portArr[0], 10, 0)
			highPort, err := strconv.ParseInt(portArr[1], 10, 0)
			if err != nil {
				return res, fmt.Errorf("Invalid port range %s", portRange)
			}
			if lowPort > highPort {
				return res, fmt.Errorf("Invalid port range %s", portRange)
			}
			for i := lowPort; i <= highPort; i++ {
				res = append(res, i)
			}
		default:
			return res, fmt.Errorf("Invalid port range %s", portRange)
		}
	}
	return res, nil
}
