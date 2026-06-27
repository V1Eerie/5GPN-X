package main

import (
	"bytes"
	"net"
	"testing"
)

func TestExtractARecordsReturnsEmptyForQuery(t *testing.T) {
	// A DNS query (not a response) should return nil
	query := DNSQuery(0x1234, "example.com")
	ips := extractARecords(query)
	if len(ips) != 0 {
		t.Fatalf("extractARecords on query returned %v, want empty", ips)
	}
}

func TestExtractARecordsParsesSingleARecord(t *testing.T) {
	query := DNSQuery(0x1234, "example.com")
	response := DNSResponseWithA(query, 0x1234, 1, "93.184.216.34")

	ips := extractARecords(response)
	if len(ips) != 1 {
		t.Fatalf("extractARecords returned %d IPs, want 1", len(ips))
	}
	if ips[0].String() != "93.184.216.34" {
		t.Fatalf("extractARecords returned %s, want 93.184.216.34", ips[0].String())
	}
}

func TestExtractARecordsParsesMultipleARecords(t *testing.T) {
	query := DNSQuery(0x5678, "google.com")
	response := DNSResponseWithA(query, 0x5678, 2, "142.250.80.46", "142.250.80.78")

	ips := extractARecords(response)
	if len(ips) != 2 {
		t.Fatalf("extractARecords returned %d IPs, want 2", len(ips))
	}
	if ips[0].String() != "142.250.80.46" {
		t.Fatalf("extractARecords[0] = %s, want 142.250.80.46", ips[0].String())
	}
}

func TestExtractARecordsReturnsEmptyForNXDOMAIN(t *testing.T) {
	query := DNSQuery(0x9012, "nonexistent.example.com")
	response := DNSNXDOMAIN(query, 0x9012)

	ips := extractARecords(response)
	if len(ips) != 0 {
		t.Fatalf("extractARecords on NXDOMAIN returned %v, want empty", ips)
	}
}

func TestDNSSpoofResponseCreatesValidSpoof(t *testing.T) {
	query := DNSQuery(0xabcd, "overseas-site.com")
	spoofIP := net.ParseIP("203.0.113.1").To4()

	spoofed := dnsSpoofResponse(query, spoofIP)
	if spoofed == nil {
		t.Fatalf("dnsSpoofResponse returned nil")
	}

	// Check transaction ID matches
	if spoofed[0] != query[0] || spoofed[1] != query[1] {
		t.Fatalf("transaction ID doesn't match")
	}

	// Check QR bit is set
	if spoofed[2]&0x80 == 0 {
		t.Fatalf("QR bit not set in spoofed response")
	}

	// Check ANCOUNT = 1
	ancount := int(spoofed[6])<<8 | int(spoofed[7])
	if ancount != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", ancount)
	}

	// Extract the IP from the spoofed response
	ips := extractARecords(spoofed)
	if len(ips) != 1 {
		t.Fatalf("extractARecords from spoofed returned %d IPs, want 1", len(ips))
	}
	if !bytes.Equal(ips[0], spoofIP) {
		t.Fatalf("spoofed IP = %s, want %s", ips[0].String(), spoofIP.String())
	}
}

func TestValidDNSResponseRecognizesResponse(t *testing.T) {
	query := DNSQuery(0x1111, "test.com")
	response := DNSResponseWithA(query, 0x1111, 1, "1.2.3.4")

	if !validDNSResponse(query, response) {
		t.Fatalf("validDNSResponse returned false for valid response")
	}

	// Query should not be a valid "response"
	if validDNSResponse(query, query) {
		t.Fatalf("validDNSResponse returned true for a query")
	}

	// Empty response should fail
	if validDNSResponse(query, nil) {
		t.Fatalf("validDNSResponse returned true for nil")
	}

	if validDNSResponse(query, []byte{}) {
		t.Fatalf("validDNSResponse returned true for empty")
	}
}

func TestDNSErrorResponseIsServfail(t *testing.T) {
	query := DNSQuery(0x3333, "fail.example.com")
	errorResp := dnsErrorResponse(query, 2) // SERVFAIL

	if errorResp == nil {
		t.Fatalf("dnsErrorResponse returned nil")
	}

	// Check SERVFAIL rcode
	if rcode := errorResp[3] & 0x0f; rcode != 2 {
		t.Fatalf("rcode = %d, want 2 (SERVFAIL)", rcode)
	}

	// Check ANCOUNT = 0
	ancount := int(errorResp[6])<<8 | int(errorResp[7])
	if ancount != 0 {
		t.Fatalf("ANCOUNT = %d, want 0", ancount)
	}
}

func TestParseUpstreamListHandlesVariousFormats(t *testing.T) {
	// Default case: IPs without port
	list := parseUpstreamList("1.1.1.1,8.8.8.8")
	if len(list) != 2 || list[0] != "1.1.1.1:53" || list[1] != "8.8.8.8:53" {
		t.Fatalf("got %v, want [1.1.1.1:53 8.8.8.8:53]", list)
	}

	// With ports
	list = parseUpstreamList("1.1.1.1:53,8.8.8.8:53")
	if len(list) != 2 || list[0] != "1.1.1.1:53" || list[1] != "8.8.8.8:53" {
		t.Fatalf("with ports: got %v", list)
	}

	// Space-separated
	list = parseUpstreamList("1.1.1.1 8.8.8.8")
	if len(list) != 2 {
		t.Fatalf("space-separated: got %d, want 2", len(list))
	}

	// Empty
	list = parseUpstreamList("")
	if len(list) != 0 {
		t.Fatalf("empty: got %d, want 0", len(list))
	}
}

// Test helpers - construct DNS query packets

func DNSQuery(id uint16, domain string) []byte {
	// Build a minimal DNS query
	var buf bytes.Buffer

	// Header
	buf.Write([]byte{byte(id >> 8), byte(id)}) // ID
	buf.Write([]byte{0x01, 0x00})               // flags: RD=1
	buf.Write([]byte{0x00, 0x01})               // QDCOUNT = 1
	buf.Write([]byte{0x00, 0x00})               // ANCOUNT = 0
	buf.Write([]byte{0x00, 0x00})               // NSCOUNT = 0
	buf.Write([]byte{0x00, 0x00})               // ARCOUNT = 0

	// Question: encode domain name
	for _, part := range bytes.Split([]byte(domain), []byte{'.'}) {
		buf.WriteByte(byte(len(part)))
		buf.Write(part)
	}
	buf.WriteByte(0x00) // root label

	// QTYPE = A (1), QCLASS = IN (1)
	buf.Write([]byte{0x00, 0x01, 0x00, 0x01})

	return buf.Bytes()
}

func DNSResponseWithA(query []byte, id uint16, count int, ips ...string) []byte {
	var buf bytes.Buffer

	// Header
	buf.Write([]byte{byte(id >> 8), byte(id)}) // ID
	buf.Write([]byte{0x81, 0x80})               // flags: QR=1, RD=1, RA=1
	buf.Write([]byte{0x00, 0x01})               // QDCOUNT = 1

	ancount := count
	if ancount > len(ips) {
		ancount = len(ips)
	}
	buf.Write([]byte{byte(ancount >> 8), byte(ancount)}) // ANCOUNT
	buf.Write([]byte{0x00, 0x00})                         // NSCOUNT
	buf.Write([]byte{0x00, 0x00})                         // ARCOUNT

	// Question section (copy from query)
	// Find end of question in query
	end := 12
	qdcount := int(query[4])<<8 | int(query[5])
	for i := 0; i < qdcount; i++ {
		for {
			labelLen := int(query[end])
			end++
			if labelLen == 0 {
				break
			}
			if labelLen&0xc0 == 0xc0 {
				end++
				break
			}
			end += labelLen
		}
		end += 4 // QTYPE + QCLASS
	}
	buf.Write(query[12:end])

	// Answer section
	for i := 0; i < ancount && i < len(ips); i++ {
		ip := net.ParseIP(ips[i]).To4()
		if ip == nil {
			continue
		}

		// Name pointer (compressed, points to offset 12)
		buf.Write([]byte{0xc0, 0x0c})
		// TYPE = A
		buf.Write([]byte{0x00, 0x01})
		// CLASS = IN
		buf.Write([]byte{0x00, 0x01})
		// TTL = 300
		buf.Write([]byte{0x00, 0x00, 0x01, 0x2c})
		// RDLENGTH = 4
		buf.Write([]byte{0x00, 0x04})
		// RDATA
		buf.Write(ip)
	}

	return buf.Bytes()
}

func DNSNXDOMAIN(query []byte, id uint16) []byte {
	var buf bytes.Buffer

	// Header
	buf.Write([]byte{byte(id >> 8), byte(id)}) // ID
	buf.Write([]byte{0x81, 0x83})               // flags: QR=1, RD=1, RA=1, RCODE=3 (NXDOMAIN)
	buf.Write([]byte{0x00, 0x01})               // QDCOUNT = 1
	buf.Write([]byte{0x00, 0x00})               // ANCOUNT = 0
	buf.Write([]byte{0x00, 0x00})               // NSCOUNT
	buf.Write([]byte{0x00, 0x00})               // ARCOUNT

	// Question section
	end := 12
	qdcount := int(query[4])<<8 | int(query[5])
	for i := 0; i < qdcount; i++ {
		for {
			labelLen := int(query[end])
			end++
			if labelLen == 0 {
				break
			}
			if labelLen&0xc0 == 0xc0 {
				end++
				break
			}
			end += labelLen
		}
		end += 4
	}
	buf.Write(query[12:end])

	return buf.Bytes()
}
