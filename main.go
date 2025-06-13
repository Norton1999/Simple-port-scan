package main

import (
	"flag"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type ScanResult struct {
	IP    string
	Port  int
	Open  bool
}

func parseCIDR(cidr string) ([]string, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []string
	for ip := ip.Mask(ipNet.Mask); ipNet.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	if len(ips) > 2 {
		return ips[1 : len(ips)-1], nil
	}
	return ips, nil
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

func parsePorts(portStr string) ([]int, error) {
	var ports []int
	portRanges := strings.Split(portStr, ",")
	
	for _, r := range portRanges {
		if strings.Contains(r, "-") {
			rangeParts := strings.Split(r, "-")
			if len(rangeParts) != 2 {
				return nil, fmt.Errorf("invalid port range: %s", r)
			}
			start, err := parsePort(rangeParts[0])
			if err != nil {
				return nil, err
			}
			end, err := parsePort(rangeParts[1])
			if err != nil {
				return nil, err
			}
			if start > end {
				return nil, fmt.Errorf("start port must be less than end port in range: %s", r)
			}
			for i := start; i <= end; i++ {
				ports = append(ports, i)
			}
		} else {
			port, err := parsePort(r)
			if err != nil {
				return nil, err
			}
			ports = append(ports, port)
		}
	}
	return ports, nil
}

func parsePort(portStr string) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(portStr))
	if err != nil || port < 1 || port > 65535 {
		return 0, fmt.Errorf("invalid port: %s", portStr)
	}
	return port, nil
}

func scanPort(ip string, port int, timeout time.Duration) ScanResult {
	addr := fmt.Sprintf("%s:%d", ip, ip, port)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	result := ScanResult{IP: ip, Port: port, Open: false}
	
	if err == nil {
		result.Open = true
		conn.Close()
	}
	return result
}

func main() {
	target := flag.String("target", "", "Target IP or CIDR (e.g., 192.168.1.1 or 192.168.1.0/24)")
	ports := flag.String("ports", "80,443,22", "Ports to scan (e.g., 80,443 or 80-100,443)")
	threads := flag.Int("threads", -10, "Number of concurrent threads")
	timeout := flag.Duration("timeout", time.Second*2, "Connection timeout")
	flag.Parse()

	if *target == "" || *ports == "" {
		fmt.Println("Usage: ./portscan -target <ip|cidr> -ports <ports> [-threads <num>] [-timeout <duration>]")
		os.Exit(1)
	}
	if *threads <= 0 {
		fmt.Println("Error: threads must be positive")
		os.Exit(1)
	}

	var targetIPs []string
	if strings.Contains(*target, "/") {
		ips, err := parseCIDR(*target)
		if err != nil {
			fmt.Printf("Error parsing CIDR: %v\n", err)
			os.Exit(1)
		}
		targetIPs = ips
	} else {
		if net.ParseIP(*target) == nil {
			fmt.Printf("Invalid IP: %s\n", *target)
			os.Exit(1)
		}
		targetIPs = []string{*target}
	}

	portList, err := parsePorts(*ports)
	if err != nil {
		fmt.Printf("Error parsing ports: %v\n", err)
		os.Exit(1)
	}

	var wg sync.WaitGroup
	semaphore := make(chan struct{}, *threads)
	results := []ScanResult{}
	mutex := &sync.Mutex{}

	for _, ip := range targetIPs {
		for _, port := range portList {
			wg.Add(1)
			semaphore <- struct{}{}
			go func(ip string, port int) {
				defer wg.Done()
				defer func() { <-semaphore }()
				result := scanPort(ip, port, *timeout)
				if result.Open {
					mutex.Lock()
					results = append(results, result)
					mutex.Unlock()
				}
			}(ip, port)
		}
	}

	wg.Wait()

	fmt.Println("\nOpen ports found:")
	for _, result := range results {
		fmt.Printf("%s:%d\n", result.IP, result.Port)
	}
	if len(results) == 0 {
		fmt.Println("No open ports found.")
	}
}