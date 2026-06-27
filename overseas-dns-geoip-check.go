// overseas-dns-geoip-check.go - Overseas DNS proxy with GeoIP spoofing.
//
// Listens on localhost, forwards each DNS query to several overseas DNS
// upstreams in parallel, then checks the resolved A records against a
// MaxMind DB (MMDB) geoip database (geoip-cn.db).
//
// If ANY resolved IP is NOT in the China geoip database, the response is
// replaced with the server's own IP address (DNS spoofing), causing the
// client's traffic to be routed through the local transparent proxy.
// If ALL resolved IPs are in China, the normal DNS response is returned
// so the client connects directly.
//
// This catches domains that should be proxied but aren't on the GFWList,
// by checking whether they actually resolve to overseas IPs.
//
// Build:
//
//	export GOPATH=/tmp/gopath
//	go mod init overseas-dns-geoip-check
//	go get github.com/oschwald/maxminddb-golang@v1.12.0
//	go build -ldflags="-s -w" -o overseas-dns-geoip-check overseas-dns-geoip-check.go
//
// Run:
//
//	./overseas-dns-geoip-check -l 127.0.0.1:5302 \
//	  -upstreams "1.1.1.1:53,8.8.8.8:53" \
//	  -geoip-db /etc/dnsdist/geoip-cn.db \
//	  -spoof-ip 203.0.113.1

package main

import (
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

var (
	geoipListenAddr = flag.String("l", "127.0.0.1:5302", "Listen address")
	geoipUpstreams  = flag.String("upstreams", "1.1.1.1:53,8.8.8.8:53", "Overseas DNS upstreams")
	geoipDBPath     = flag.String("geoip-db", "/etc/dnsdist/geoip-cn.db", "Path to geoip-cn.db (MMDB format)")
	geoipSpoofIP    = flag.String("spoof-ip", "", "Server IP to return for spoofed responses (auto-detect if empty)")
	geoipTimeout    = flag.Duration("timeout", 3*time.Second, "Per-query timeout")
	geoipReload     = flag.Duration("reload-interval", 5*time.Minute, "GeoIP DB reload interval (0 = no reload)")
)

// geoIPReader wraps the MMDB reader with reload capability.
type geoIPReader struct {
	mu     sync.RWMutex
	reader *maxminddb.Reader
	path   string
}

func newGeoIPReader(path string) (*geoIPReader, error) {
	r, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open geoip db %s: %w", path, err)
	}
	return &geoIPReader{reader: r, path: path}, nil
}

func (g *geoIPReader) reload() error {
	r, err := maxminddb.Open(g.path)
	if err != nil {
		return fmt.Errorf("reload geoip db %s: %w", g.path, err)
	}
	g.mu.Lock()
	old := g.reader
	g.reader = r
	g.mu.Unlock()
	old.Close()
	return nil
}

func (g *geoIPReader) isIPInChina(ip net.IP) bool {
	g.mu.RLock()
	r := g.reader
	g.mu.RUnlock()
	if r == nil {
		return false
	}
	var result interface{}
	if err := r.Lookup(ip, &result); err != nil {
		return false
	}
	// Successful lookup with non-nil result means the IP is in the China DB.
	return result != nil
}

func (g *geoIPReader) close() {
	g.mu.Lock()
	if g.reader != nil {
		g.reader.Close()
		g.reader = nil
	}
	g.mu.Unlock()
}

func main() {
	flag.Parse()

	upstreams := parseUpstreamList(*geoipUpstreams)
	if len(upstreams) == 0 {
		log.Fatal("no upstreams configured")
	}

	// Determine spoof IP
	spoofIP := *geoipSpoofIP
	if spoofIP == "" {
		ip, err := detectPublicIP()
		if err != nil {
			log.Fatalf("cannot detect public IP: %v; set -spoof-ip explicitly", err)
		}
		spoofIP = ip
		log.Printf("auto-detected spoof IP: %s", spoofIP)
	}
	spoofParsed := net.ParseIP(spoofIP)
	if spoofParsed == nil {
		log.Fatalf("invalid spoof IP: %s", spoofIP)
	}
	spoofParsed = spoofParsed.To4()
	if spoofParsed == nil {
		log.Fatalf("spoof IP is not an IPv4 address: %s", spoofIP)
	}

	// Open geoip DB
	geoip, err := newGeoIPReader(*geoipDBPath)
	if err != nil {
		log.Printf("WARNING: cannot open geoip db %s: %v", *geoipDBPath, err)
		log.Printf("Will run in pass-through mode (no geoip spoofing) until DB becomes available")
		geoip = &geoIPReader{reader: nil, path: *geoipDBPath}
	}

	// Periodic reload
	if *geoipReload > 0 {
		go func() {
			ticker := time.NewTicker(*geoipReload)
			defer ticker.Stop()
			for range ticker.C {
				if err := geoip.reload(); err != nil {
					log.Printf("geoip db reload error: %v", err)
				} else {
					log.Printf("geoip db reloaded from %s", geoip.path)
				}
			}
		}()
	}

	// Reload on SIGHUP
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGHUP)
	go func() {
		for range sigCh {
			log.Printf("received SIGHUP, reloading geoip db...")
			if err := geoip.reload(); err != nil {
				log.Printf("geoip db reload error: %v", err)
			} else {
				log.Printf("geoip db reloaded from %s", geoip.path)
			}
		}
	}()

	udpConn, err := net.ListenPacket("udp", *geoipListenAddr)
	if err != nil {
		log.Fatalf("ListenPacket udp: %v", err)
	}
	defer udpConn.Close()

	tcpListener, err := net.Listen("tcp", *geoipListenAddr)
	if err != nil {
		log.Fatalf("Listen tcp: %v", err)
	}
	defer tcpListener.Close()

	log.Printf("Overseas DNS geoip check proxy listening on %s (udp/tcp)", *geoipListenAddr)
	log.Printf("upstreams: %s", strings.Join(upstreams, ","))
	log.Printf("geoip db: %s", *geoipDBPath)
	log.Printf("spoof IP: %s", spoofIP)
	log.Printf("timeout: %s", *geoipTimeout)
	if geoip.reader == nil {
		log.Printf("mode: pass-through (no geoip db)")
	} else {
		log.Printf("mode: geoip spoofing active")
	}

	go serveTCP(tcpListener, upstreams, spoofParsed, geoip, *geoipTimeout)
	serveUDP(udpConn, upstreams, spoofParsed, geoip, *geoipTimeout)
}

func detectPublicIP() (string, error) {
	// Try several methods to find the public IP
	// 1. Try to connect and check the source IP
	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 3*time.Second)
	if err == nil {
		localAddr := conn.LocalAddr().(*net.UDPAddr)
		conn.Close()
		if localAddr.IP.To4() != nil && !localAddr.IP.IsLoopback() {
			return localAddr.IP.String(), nil
		}
	}

	// 2. Fallback: use the IP of the default route interface
	interfaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range interfaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				ipnet, ok := addr.(*net.IPNet)
				if !ok {
					continue
				}
				ip4 := ipnet.IP.To4()
				if ip4 == nil {
					continue
				}
				// Skip private IPs
				if ip4[0] == 10 || ip4[0] == 172 || ip4[0] == 192 || ip4.IsLoopback() {
					continue
				}
				return ip4.String(), nil
			}
		}
	}

	return "", fmt.Errorf("could not determine public IP")
}

func serveUDP(conn net.PacketConn, upstreams []string, spoofIP net.IP, geoip *geoIPReader, timeout time.Duration) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			log.Printf("ReadFrom: %v", err)
			continue
		}
		query := append([]byte(nil), buf[:n]...)
		go handleUDPQuery(conn, addr, query, upstreams, spoofIP, geoip, timeout)
	}
}

func serveTCP(listener net.Listener, upstreams []string, spoofIP net.IP, geoip *geoIPReader, timeout time.Duration) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept tcp: %v", err)
			continue
		}
		go handleTCPConnection(conn, upstreams, spoofIP, geoip, timeout)
	}
}

func handleUDPQuery(conn net.PacketConn, addr net.Addr, query []byte, upstreams []string, spoofIP net.IP, geoip *geoIPReader, timeout time.Duration) {
	response, err := queryGeoipChecked(query, upstreams, spoofIP, geoip, timeout)
	if err != nil {
		log.Printf("[%s] DNS query failed: %v", addr.String(), err)
		response = dnsErrorResponse(query, 2) // SERVFAIL
		if response == nil {
			return
		}
	}
	if _, err := conn.WriteTo(response, addr); err != nil {
		log.Printf("[%s] WriteTo: %v", addr.String(), err)
	}
}

func handleTCPConnection(conn net.Conn, upstreams []string, spoofIP net.IP, geoip *geoIPReader, timeout time.Duration) {
	defer conn.Close()

	for {
		lengthBytes := make([]byte, 2)
		if _, err := io.ReadFull(conn, lengthBytes); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				log.Printf("[%s] Read TCP query length: %v", conn.RemoteAddr().String(), err)
			}
			return
		}
		queryLen := int(binary.BigEndian.Uint16(lengthBytes))
		if queryLen < 12 {
			log.Printf("[%s] TCP query too short: %d", conn.RemoteAddr().String(), queryLen)
			return
		}

		query := make([]byte, queryLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			log.Printf("[%s] Read TCP query: %v", conn.RemoteAddr().String(), err)
			return
		}

		response, err := queryGeoipChecked(query, upstreams, spoofIP, geoip, timeout)
		if err != nil {
			log.Printf("[%s] TCP DNS query failed: %v", conn.RemoteAddr().String(), err)
			response = dnsErrorResponse(query, 2) // SERVFAIL
			if response == nil {
				return
			}
		}
		if len(response) > 65535 {
			log.Printf("[%s] TCP response too large: %d", conn.RemoteAddr().String(), len(response))
			return
		}

		framedResponse := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(framedResponse[:2], uint16(len(response)))
		copy(framedResponse[2:], response)
		if _, err := conn.Write(framedResponse); err != nil {
			log.Printf("[%s] Write TCP response: %v", conn.RemoteAddr().String(), err)
			return
		}
	}
}

// queryGeoipChecked queries the overseas DNS upstreams and checks the
// resolved IPs against the geoip database. Returns either the original
// DNS response (if all IPs are in China) or a spoofed response with the
// server IP (if any IP is overseas).
func queryGeoipChecked(query []byte, upstreams []string, spoofIP net.IP, geoip *geoIPReader, timeout time.Duration) ([]byte, error) {
	response, err := raceQuery(query, upstreams, timeout)
	if err != nil {
		return nil, err
	}

	// Extract A records from the response
	ips := extractARecords(response)
	if len(ips) == 0 {
		// No A records to check (e.g., NXDOMAIN, CNAME-only, no answer)
		return response, nil
	}

	// If geoip db is not loaded, pass through
	if geoip == nil || geoip.reader == nil {
		return response, nil
	}

	// Check each resolved IP against the China geoip database
	allInChina := true
	for _, ip := range ips {
		if !geoip.isIPInChina(ip) {
			allInChina = false
			break
		}
	}

	if allInChina {
		// All IPs are in China → return normal response (direct connection)
		return response, nil
	}

	// At least one IP is overseas → spoof: return server IP
	return dnsSpoofResponse(query, spoofIP), nil
}

// raceQuery forwards the query to all upstreams in parallel and returns
// the first valid response.
func raceQuery(query []byte, upstreams []string, timeout time.Duration) ([]byte, error) {
	if len(query) < 2 {
		return nil, errors.New("query too short")
	}

	type result struct {
		data []byte
		err  error
	}

	results := make(chan result, len(upstreams))
	ctx := &raceContext{
		query:    query,
		upstreams: upstreams,
		results:  results,
		timeout:  timeout,
	}

	// Fire all queries in parallel
	for _, upstream := range upstreams {
		upstream := upstream
		go func() {
			resp, err := queryUDPUpstream(ctx.query, upstream, ctx.timeout)
			if err != nil || !validDNSResponse(ctx.query, resp) {
				results <- result{err: err}
				return
			}
			results <- result{data: resp}
		}()
	}

	// Wait for first valid response or timeout
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	received := 0
	for {
		select {
		case res := <-results:
			received++
			if res.data != nil {
				return res.data, nil
			}
			if received >= len(upstreams) {
				return nil, fmt.Errorf("all upstreams failed")
			}
		case <-timer.C:
			return nil, errors.New("all upstreams timed out")
		}
	}
}

type raceContext struct {
	query     []byte
	upstreams []string
	results   chan result
	timeout   time.Duration
}

type result struct {
	data []byte
	err  error
}

func queryUDPUpstream(query []byte, upstream string, timeout time.Duration) ([]byte, error) {
	conn, err := net.DialTimeout("udp", upstream, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return append([]byte(nil), buf[:n]...), nil
}

// extractARecords parses a DNS response and returns all IPv4 (A record)
// addresses found in the answer section.
func extractARecords(response []byte) []net.IP {
	if len(response) < 12 {
		return nil
	}

	// Check that it's a response (QR bit set)
	if response[2]&0x80 == 0 {
		return nil
	}

	ancount := int(response[6])<<8 | int(response[7])
	if ancount == 0 {
		return nil
	}

	// Parse the question section to find where answers start
	end := 12
	qdcount := int(response[4])<<8 | int(response[5])
	for i := 0; i < qdcount; i++ {
		for {
			if end >= len(response) {
				return nil
			}
			labelLen := int(response[end])
			end++
			if labelLen == 0 {
				break
			}
			if labelLen&0xc0 == 0xc0 {
				if end >= len(response) {
					return nil
				}
				end++
				break
			}
			if end+labelLen > len(response) {
				return nil
			}
			end += labelLen
		}
		if end+4 > len(response) {
			return nil
		}
		end += 4 // skip QTYPE and QCLASS
	}

	var ips []net.IP
	for i := 0; i < ancount && end+12 <= len(response); i++ {
		// Parse answer name (could be compressed)
		if end >= len(response) {
			break
		}
		if response[end]&0xc0 == 0xc0 {
			end += 2
		} else {
			for {
				if end >= len(response) {
					return ips
				}
				labelLen := int(response[end])
				end++
				if labelLen == 0 {
					break
				}
				if end+labelLen > len(response) {
					return ips
				}
				end += labelLen
			}
		}
		if end+10 > len(response) {
			break
		}
		rtype := int(response[end])<<8 | int(response[end+1])
		rdlength := int(response[end+8])<<8 | int(response[end+9])
		end += 10

		if rtype == 1 && rdlength == 4 && end+4 <= len(response) { // A record
			ip := net.IP(response[end : end+4])
			ips = append(ips, ip)
		}
		end += rdlength
	}
	return ips
}

// dnsSpoofResponse creates a DNS response that points to the given IP,
// spoofing the original query.
func dnsSpoofResponse(query []byte, ip net.IP) []byte {
	if len(query) < 12 {
		return nil
	}

	// Parse question to find the end
	end := 12
	qdcount := int(query[4])<<8 | int(query[5])
	if qdcount == 0 {
		return nil
	}

	for i := 0; i < qdcount; i++ {
		for {
			if end >= len(query) {
				return nil
			}
			labelLen := int(query[end])
			end++
			if labelLen == 0 {
				break
			}
			if labelLen&0xc0 == 0xc0 {
				if end >= len(query) {
					return nil
				}
				end++
				break
			}
			if labelLen&0xc0 != 0 || end+labelLen > len(query) {
				return nil
			}
			end += labelLen
		}
		if end+4 > len(query) {
			return nil
		}
		// Save QTYPE and QCLASS
		qtype := query[end : end+2]
		_ = qtype
		end += 4
	}

	questionLen := end

	// Build response: header + question + answer
	response := make([]byte, questionLen+16)
	copy(response[:questionLen], query[:questionLen])

	// Set QR bit (response), preserve opcode
	flags := uint16(response[2])<<8 | uint16(response[3])
	flags |= 0x8000 // QR=1 (response)
	flags &^= 0x000f // clear RCODE
	response[2] = byte(flags >> 8)
	response[3] = byte(flags)

	// Set ANCOUNT = 1
	response[6] = 0
	response[7] = 1

	// Set answer section: pointer to query name (0xc00c = offset 12)
	qtype := query[questionLen-4 : questionLen-2]
	qclass := query[questionLen-2 : questionLen]

	off := questionLen
	response[off] = 0xc0 // compressed name pointer
	response[off+1] = 0x0c // points to offset 12 in header
	off += 2
	copy(response[off:off+2], qtype) // TYPE = A (from query)
	off += 2
	copy(response[off:off+2], qclass) // CLASS = IN (from query)
	off += 2
	// TTL = 300 seconds
	response[off] = 0
	response[off+1] = 0
	response[off+2] = 1
	response[off+3] = 0x2c // 300 = 0x12c
	off += 4
	// RDLENGTH = 4
	response[off] = 0
	response[off+1] = 4
	off += 2
	// RDATA = IP
	response[off] = ip[0]
	response[off+1] = ip[1]
	response[off+2] = ip[2]
	response[off+3] = ip[3]

	return response
}

func validDNSResponse(query []byte, response []byte) bool {
	if len(query) < 2 || len(response) < 12 {
		return false
	}
	// Transaction ID must match
	if response[0] != query[0] || response[1] != query[1] {
		return false
	}
	// QR bit must be set (it's a response)
	return response[2]&0x80 != 0
}

func dnsErrorResponse(query []byte, rcode byte) []byte {
	if len(query) < 12 {
		return nil
	}

	end := 12
	qdCount := int(query[4])<<8 | int(query[5])
	for i := 0; i < qdCount; i++ {
		for {
			if end >= len(query) {
				return nil
			}
			labelLen := int(query[end])
			end++
			if labelLen == 0 {
				break
			}
			if labelLen&0xc0 == 0xc0 {
				if end >= len(query) {
					return nil
				}
				end++
				break
			}
			if labelLen&0xc0 != 0 || end+labelLen > len(query) {
				return nil
			}
			end += labelLen
		}
		if end+4 > len(query) {
			return nil
		}
		end += 4
	}

	response := append([]byte(nil), query[:end]...)
	flags := uint16(response[2])<<8 | uint16(response[3])
	flags |= 0x8000
	flags &^= 0x000f
	flags |= uint16(rcode & 0x0f)
	response[2] = byte(flags >> 8)
	response[3] = byte(flags)
	response[6] = 0
	response[7] = 0
	response[8] = 0
	response[9] = 0
	response[10] = 0
	response[11] = 0
	return response
}

func parseUpstreamList(input string) []string {
	var upstreams []string
	for _, item := range strings.FieldsFunc(input, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(item); err != nil {
			item = net.JoinHostPort(item, "53")
		}
		upstreams = append(upstreams, item)
	}
	return upstreams
}
