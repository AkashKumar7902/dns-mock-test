package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/miekg/dns"
)

// DNSResponse represents the JSON response structure
type DNSResponse struct {
	Domain  string   `json:"domain"`
	Type    string   `json:"type"`
	Records []string `json:"records"`
	Error   string   `json:"error,omitempty"`
}

// MXResponse represents the JSON response for MX records
type MXResponse struct {
	Domain  string     `json:"domain"`
	Type    string     `json:"type"`
	Records []MXRecord `json:"records"`
	Error   string     `json:"error,omitempty"`
}

type MXRecord struct {
	Host     string `json:"host"`
	Priority uint16 `json:"priority"`
}

// SRVResponse represents the JSON response for SRV records
type SRVResponse struct {
	Domain  string      `json:"domain"`
	Type    string      `json:"type"`
	Records []SRVRecord `json:"records"`
	Error   string      `json:"error,omitempty"`
}

type SRVRecord struct {
	Target   string `json:"target"`
	Port     uint16 `json:"port"`
	Priority uint16 `json:"priority"`
	Weight   uint16 `json:"weight"`
}

// Handler for A records (IPv4) - Force TCP
func handleARecord(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondWithError(w, "domain parameter is required", http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeA)
	if err != nil {
		respondWithJSON(w, DNSResponse{
			Domain: domain,
			Type:   "A",
			Error:  err.Error(),
		})
		return
	}

	var ipv4s []string
	for _, rr := range records {
		if a, ok := rr.(*dns.A); ok {
			ipv4s = append(ipv4s, a.A.String())
		}
	}

	respondWithJSON(w, DNSResponse{
		Domain:  domain,
		Type:    "A",
		Records: ipv4s,
	})
}

// Handler for AAAA records (IPv6) - Force TCP
func handleAAAARecord(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondWithError(w, "domain parameter is required", http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeAAAA)
	if err != nil {
		respondWithJSON(w, DNSResponse{
			Domain: domain,
			Type:   "AAAA",
			Error:  err.Error(),
		})
		return
	}

	var ipv6s []string
	for _, rr := range records {
		if aaaa, ok := rr.(*dns.AAAA); ok {
			ipv6s = append(ipv6s, aaaa.AAAA.String())
		}
	}

	respondWithJSON(w, DNSResponse{
		Domain:  domain,
		Type:    "AAAA",
		Records: ipv6s,
	})
}

// Handler for TXT records - Force TCP
func handleTXTRecord(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondWithError(w, "domain parameter is required", http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeTXT)
	if err != nil {
		respondWithJSON(w, DNSResponse{
			Domain: domain,
			Type:   "TXT",
			Error:  err.Error(),
		})
		return
	}

	var txts []string
	for _, rr := range records {
		if txt, ok := rr.(*dns.TXT); ok {
			for _, t := range txt.Txt {
				txts = append(txts, t)
			}
		}
	}

	respondWithJSON(w, DNSResponse{
		Domain:  domain,
		Type:    "TXT",
		Records: txts,
	})
}

// Handler for CNAME records - Force TCP
func handleCNAMERecord(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondWithError(w, "domain parameter is required", http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeCNAME)
	if err != nil {
		respondWithJSON(w, DNSResponse{
			Domain: domain,
			Type:   "CNAME",
			Error:  err.Error(),
		})
		return
	}

	var cnames []string
	for _, rr := range records {
		if cname, ok := rr.(*dns.CNAME); ok {
			cnames = append(cnames, cname.Target)
		}
	}

	respondWithJSON(w, DNSResponse{
		Domain:  domain,
		Type:    "CNAME",
		Records: cnames,
	})
}

// Handler for MX records - Force TCP
func handleMXRecord(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondWithError(w, "domain parameter is required", http.StatusBadRequest)
		return
	}

	rrs, err := queryDNS(domain, dns.TypeMX)
	if err != nil {
		respondWithJSON(w, MXResponse{
			Domain: domain,
			Type:   "MX",
			Error:  err.Error(),
		})
		return
	}

	var records []MXRecord
	for _, rr := range rrs {
		if mx, ok := rr.(*dns.MX); ok {
			records = append(records, MXRecord{
				Host:     mx.Mx,
				Priority: mx.Preference,
			})
		}
	}

	respondWithJSON(w, MXResponse{
		Domain:  domain,
		Type:    "MX",
		Records: records,
	})
}

// Handler for SRV records - Force TCP
func handleSRVRecord(w http.ResponseWriter, r *http.Request) {
	service := r.URL.Query().Get("service")
	proto := r.URL.Query().Get("proto")
	name := r.URL.Query().Get("name")

	if service == "" || proto == "" || name == "" {
		respondWithError(w, "service, proto, and name parameters are required", http.StatusBadRequest)
		return
	}

	domain := fmt.Sprintf("_%s._%s.%s", service, proto, name)
	rrs, err := queryDNS(domain, dns.TypeSRV)
	if err != nil {
		respondWithJSON(w, SRVResponse{
			Domain: domain,
			Type:   "SRV",
			Error:  err.Error(),
		})
		return
	}

	var records []SRVRecord
	for _, rr := range rrs {
		if srv, ok := rr.(*dns.SRV); ok {
			records = append(records, SRVRecord{
				Target:   srv.Target,
				Port:     srv.Port,
				Priority: srv.Priority,
				Weight:   srv.Weight,
			})
		}
	}

	respondWithJSON(w, SRVResponse{
		Domain:  domain,
		Type:    "SRV",
		Records: records,
	})
}

// queryDNS performs DNS query over UDP without using the 'connect' syscall
func queryDNS(domain string, qtype uint16) ([]dns.RR, error) {
	// 1. Create the DNS message
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true
	m.SetEdns0(4096, true) // Support larger UDP packets
	m.Id = dns.Id()        // Generate random ID

	// 2. Resolve the destination address
	// This does not connect; it just parses the IP/Port
	dnsServer := "8.8.8.8:53"
	serverAddr, err := net.ResolveUDPAddr("udp", dnsServer)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve DNS server address: %v", err)
	}

	// 3. Create an UNCONNECTED UDP socket
	// Listening on Port 0 picks a random available local port.
	// This uses the 'bind' syscall, but strictly avoids 'connect'.
	localAddr, _ := net.ResolveUDPAddr("udp", ":0")
	conn, err := net.ListenUDP("udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to open UDP socket: %v", err)
	}
	defer conn.Close()

	// Set timeout for the socket
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// 4. Pack the message into bytes
	out, err := m.Pack()
	if err != nil {
		return nil, err
	}

	// 5. Send message using WriteTo (maps to 'sendto' syscall)
	_, err = conn.WriteToUDP(out, serverAddr)
	if err != nil {
		return nil, err
	}

	// 6. Receive response using ReadFrom (maps to 'recvfrom' syscall)
	// UDP packets are limited to 65535, but 4096 is standard for EDNS0
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, err
	}

	// 7. Unpack the response
	resp := new(dns.Msg)
	err = resp.Unpack(buf[:n])
	if err != nil {
		return nil, err
	}

	// Verify ID matches to ensure this is the response to our query
	if resp.Id != m.Id {
		return nil, fmt.Errorf("id mismatch: expected %d, got %d", m.Id, resp.Id)
	}

	if resp.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS query failed with code: %d", resp.Rcode)
	}

	return resp.Answer, nil
}

// Health check endpoint
func handleHealth(w http.ResponseWriter, r *http.Request) {
	respondWithJSON(w, map[string]string{"status": "healthy", "protocol": "TCP"})
}

// Helper function to respond with JSON
func respondWithJSON(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

// Helper function to respond with error
func respondWithError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(map[string]string{"error": message})
}

// Handler for MongoDB operations
// func handleMongoDB(w http.ResponseWriter, r *http.Request) {
// 	// MongoDB SRV connection string - replace with your credentials
// 	mongoURI := r.URL.Query().Get("uri")
// 	if mongoURI == "" {
// 		// Default URI format (replace with actual credentials)
// 		mongoURI = ""
// 	}

// 	// Create context with timeout
// 	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
// 	defer cancel()

// 	// Connect to MongoDB
// 	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI))
// 	if err != nil {
// 		respondWithError(w, fmt.Sprintf("Failed to connect to MongoDB: %v", err), http.StatusInternalServerError)
// 		return
// 	}
// 	defer client.Disconnect(ctx)

// 	// Ping the database
// 	err = client.Ping(ctx, nil)
// 	if err != nil {
// 		respondWithError(w, fmt.Sprintf("Failed to ping MongoDB: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	// Access database and collection
// 	database := client.Database("testdb")
// 	collection := database.Collection("documents")

// 	// Query existing documents (get the first 5 documents)
// 	cursor, err := collection.Find(ctx, bson.M{})
// 	if err != nil {
// 		respondWithError(w, fmt.Sprintf("Failed to query documents: %v", err), http.StatusInternalServerError)
// 		return
// 	}
// 	defer cursor.Close(ctx)

// 	// Decode all documents
// 	var documents []bson.M
// 	err = cursor.All(ctx, &documents)
// 	if err != nil {
// 		respondWithError(w, fmt.Sprintf("Failed to decode documents: %v", err), http.StatusInternalServerError)
// 		return
// 	}

// 	// Prepare response
// 	response := map[string]interface{}{
// 		"status":    "success",
// 		"count":     len(documents),
// 		"documents": documents,
// 		"message":   "Documents queried successfully",
// 	}

// 	respondWithJSON(w, response)
// }

func main() {
	println("PID:", os.Getpid())

	http.HandleFunc("/dns/a", handleARecord)
	http.HandleFunc("/dns/aaaa", handleAAAARecord)
	http.HandleFunc("/dns/cname", handleCNAMERecord)
	http.HandleFunc("/dns/txt", handleTXTRecord)
	http.HandleFunc("/dns/mx", handleMXRecord)
	http.HandleFunc("/dns/srv", handleSRVRecord)
	// http.HandleFunc("/mongodb", handleMongoDB)
	http.HandleFunc("/health", handleHealth)

	port := ":8086"
	log.Printf("DNS API Server starting on port %s", port)
	log.Printf("Endpoints:")
	log.Printf("  GET /dns/a?domain=<domain>")
	log.Printf("  GET /dns/aaaa?domain=<domain>")
	log.Printf("  GET /dns/cname?domain=<domain>")
	log.Printf("  GET /dns/txt?domain=<domain>")
	log.Printf("  GET /dns/mx?domain=<domain>")
	log.Printf("  GET /dns/srv?service=<service>&proto=<proto>&name=<name>")
	log.Printf("  GET /mongodb?uri=<mongodb-srv-uri>")
	log.Printf("  GET /health")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
