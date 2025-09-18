package scanner

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type Target struct {
	IP       string
	Hostname string
	Ports    []int
	Services []Service
	Vulns    []Vulnerability
}

type Service struct {
	Port     int
	Protocol string
	Name     string
	Version  string
	Banner   string
}

type Vulnerability struct {
	ID          string
	Name        string
	Severity    string
	Description string
	CVE         string
	CVSS        float64
	Proof       string
}

type Scanner struct {
	timeout     time.Duration
	workers     int
	deepScan    bool
	results     chan *Target
	vulnDB      *VulnDatabase
}

func NewScanner(timeout time.Duration, workers int, deepScan bool) *Scanner {
	return &Scanner{
		timeout:  timeout,
		workers:  workers,
		deepScan: deepScan,
		results:  make(chan *Target, 100),
		vulnDB:   NewVulnDatabase(),
	}
}

// Scan performs network scanning on the specified ports
func (s *Scanner) Scan(ctx context.Context, targets []string, ports []int) ([]*Target, error) {
	var results []*Target
	var wg sync.WaitGroup
	resultChan := make(chan *Target, len(targets))
	
	// Use default ports if none specified
	if len(ports) == 0 {
		ports = s.getDefaultPorts()
	}
	
	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()
			
			// Check if host is alive
			if !s.isHostAlive(t) {
				resultChan <- &Target{
					IP:       t,
					Hostname: "",
					Ports:    []int{},
					Services: []Service{},
					Vulns:    []Vulnerability{},
				}
				return
			}
			
			targetResult := &Target{
				IP:       t,
				Hostname: "",
				Ports:    ports,
				Services: []Service{},
				Vulns:    []Vulnerability{},
			}
			s.scanTarget(targetResult, ports)
			resultChan <- targetResult
		}(target)
	}
	
	wg.Wait()
	close(resultChan)
	
	for result := range resultChan {
		results = append(results, result)
	}
	
	return results, nil
}

func (s *Scanner) parseTargets(targetStr string) []*Target {
	var targets []*Target
	
	if strings.Contains(targetStr, "/") {
		// نطاق شبكة CIDR
		ip, ipnet, err := net.ParseCIDR(targetStr)
		if err == nil {
			for ip := ip.Mask(ipnet.Mask); ipnet.Contains(ip); inc(ip) {
				targets = append(targets, &Target{IP: ip.String()})
			}
		}
	} else if strings.Contains(targetStr, "-") {
		// نطاق IP
		parts := strings.Split(targetStr, "-")
		start := net.ParseIP(parts[0])
		end := net.ParseIP(parts[1])
		
		for ip := start; !ip.Equal(end); inc(ip) {
			targets = append(targets, &Target{IP: ip.String()})
		}
		targets = append(targets, &Target{IP: end.String()})
	} else {
		// IP أو نطاق واحد
		ips, err := net.LookupIP(targetStr)
		if err == nil && len(ips) > 0 {
			for _, ip := range ips {
				targets = append(targets, &Target{
					IP:       ip.String(),
					Hostname: targetStr,
				})
			}
		} else {
			targets = append(targets, &Target{IP: targetStr})
		}
	}
	
	return targets
}

func (s *Scanner) scanTarget(target *Target, ports []int) {
	hostnames, _ := net.LookupAddr(target.IP)
	if len(hostnames) > 0 {
		target.Hostname = hostnames[0]
	}
	
	if s.isHostAlive(target.IP) {
		target.Ports = s.scanPorts(target.IP, ports)
		target.Services = s.identifyServices(target.IP, target.Ports)
		target.Vulns = s.checkVulnerabilities(target)
	}
}

func (s *Scanner) isHostAlive(ip string) bool {
	// فحص ICMP
	if s.pingHost(ip) {
		return true
	}
	
	// فحص TCP الشائعة
	commonPorts := []int{80, 443, 22, 21, 25, 53, 135, 139, 445}
	for _, port := range commonPorts {
		if s.isPortOpen(ip, port) {
			return true
		}
	}
	
	return false
}

func (s *Scanner) pingHost(ip string) bool {
	conn, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		return false
	}
	defer conn.Close()
	
	dest, err := net.ResolveIPAddr("ip4", ip)
	if err != nil {
		return false
	}
	
	m := &icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Code: 0,
		Body: &icmp.Echo{
			ID:   1,
			Seq:  1,
			Data: []byte("vulnscan"),
		},
	}
	
	data, err := m.Marshal(nil)
	if err != nil {
		return false
	}
	
	_, err = conn.WriteTo(data, dest)
	if err != nil {
		return false
	}
	
	reply := make([]byte, 1500)
	err = conn.SetReadDeadline(time.Now().Add(s.timeout))
	if err != nil {
		return false
	}
	
	n, _, err := conn.ReadFrom(reply)
	if err != nil {
		return false
	}
	
	replyMsg, err := icmp.ParseMessage(ipv4.ICMPTypeEchoReply.Protocol(), reply[:n])
	if err != nil {
		return false
	}
	
	return replyMsg.Type == ipv4.ICMPTypeEchoReply
}

func (s *Scanner) scanPorts(ip string, ports []int) []int {
	if len(ports) == 0 {
		ports = s.getCommonPorts()
	}
	
	var openPorts []int
	var mu sync.Mutex
	var wg sync.WaitGroup
	
	semaphore := make(chan struct{}, 100)
	
	for _, port := range ports {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			semaphore <- struct{}{}
			defer func() { <-semaphore }()
			
			if s.isPortOpen(ip, p) {
				mu.Lock()
				openPorts = append(openPorts, p)
				mu.Unlock()
			}
		}(port)
	}
	
	wg.Wait()
	return openPorts
}

func (s *Scanner) isPortOpen(ip string, port int) bool {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (s *Scanner) identifyServices(ip string, ports []int) []Service {
	var services []Service
	
	for _, port := range ports {
		service := s.identifyService(ip, port)
		services = append(services, service)
	}
	
	return services
}

func (s *Scanner) identifyService(ip string, port int) Service {
	service := Service{
		Port:     port,
		Protocol: "tcp",
	}
	
	// التعرف على الخدمة من رقم المنفذ
	commonServices := map[int]string{
		21:   "ftp",
		22:   "ssh",
		23:   "telnet",
		25:   "smtp",
		53:   "dns",
		80:   "http",
		110:  "pop3",
		143:  "imap",
		443:  "https",
		3306: "mysql",
		3389: "rdp",
		5432: "postgresql",
		8080: "http-proxy",
	}
	
	if serviceName, exists := commonServices[port]; exists {
		service.Name = serviceName
	}
	
	if s.deepScan {
		service.Banner = s.grabBanner(ip, port)
		service.Version = s.detectVersion(service.Banner, service.Name)
	}
	
	return service
}

func (s *Scanner) grabBanner(ip string, port int) string {
	address := fmt.Sprintf("%s:%d", ip, port)
	conn, err := net.DialTimeout("tcp", address, s.timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	
	conn.SetReadDeadline(time.Now().Add(s.timeout))
	
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		// محاولة إرسال بيانات والقراءة
		conn.Write([]byte("HEAD / HTTP/1.0\r\n\r\n"))
		n, err = conn.Read(buffer)
		if err != nil {
			return ""
		}
	}
	
	return string(buffer[:n])
}

func (s *Scanner) detectVersion(banner, service string) string {
	if banner == "" {
		return ""
	}
	
	// تحليل البانر لاستخراج الإصدار
	// هذا مثال مبسط، يمكن تحسينه باستخدام تعبيرات منتظمة
	if service == "ssh" {
		if strings.Contains(banner, "OpenSSH") {
			parts := strings.Fields(banner)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	
	return "unknown"
}

func (s *Scanner) checkVulnerabilities(target *Target) []Vulnerability {
	var vulns []Vulnerability
	
	for _, service := range target.Services {
		serviceVulns := s.vulnDB.CheckService(service.Name, service.Version)
		vulns = append(vulns, serviceVulns...)
		
		if s.deepScan {
			bannerVulns := s.vulnDB.CheckBanner(service.Banner)
			vulns = append(vulns, bannerVulns...)
		}
	}
	
	return vulns
}

func (s *Scanner) getCommonPorts() []int {
	return []int{
		21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995,
		1723, 3306, 3389, 5900, 8080, 8443, 8888, 1433, 1521, 5432,
	}
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getDefaultPorts returns the most common ports to scan
func (s *Scanner) getDefaultPorts() []int {
	return []int{
		21,    // FTP
		22,    // SSH
		23,    // Telnet
		25,    // SMTP
		53,    // DNS
		80,    // HTTP
		110,   // POP3
		111,   // RPC
		135,   // MSRPC
		139,   // NetBIOS
		143,   // IMAP
		443,   // HTTPS
		445,   // SMB
		993,   // IMAPS
		995,   // POP3S
		1433,  // MSSQL
		1521,  // Oracle
		3306,  // MySQL
		3389,  // RDP
		5432,  // PostgreSQL
		5900,  // VNC
		8080,  // HTTP Proxy
		8443,  // HTTPS Alt
		9200,  // Elasticsearch
		27017, // MongoDB
	}
}