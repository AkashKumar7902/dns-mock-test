package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"

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

func getTransport(r *http.Request) (string, error) {
	transport := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("transport")))
	if transport == "" {
		return "udp4", nil
	}
	if transport != "udp4" && transport != "udp6" {
		return "", fmt.Errorf("transport must be udp4 or udp6")
	}
	return transport, nil
}

// Handler for A records (IPv4) - Force TCP
func handleARecord(w http.ResponseWriter, r *http.Request) {
	domain := r.URL.Query().Get("domain")
	if domain == "" {
		respondWithError(w, "domain parameter is required", http.StatusBadRequest)
		return
	}

	transport, err := getTransport(r)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeA, transport)
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

	transport, err := getTransport(r)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeAAAA, transport)
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

	transport, err := getTransport(r)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeTXT, transport)
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

	transport, err := getTransport(r)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	records, err := queryDNS(domain, dns.TypeCNAME, transport)
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

	transport, err := getTransport(r)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	rrs, err := queryDNS(domain, dns.TypeMX, transport)
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

	transport, err := getTransport(r)
	if err != nil {
		respondWithError(w, err.Error(), http.StatusBadRequest)
		return
	}

	domain := fmt.Sprintf("_%s._%s.%s", service, proto, name)
	rrs, err := queryDNS(domain, dns.TypeSRV, transport)
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

// queryDNS performs DNS query using udp4/udp6 over connected UDP sockets.
func queryDNS(domain string, qtype uint16, transport string) ([]dns.RR, error) {
	c := new(dns.Client)

	dnsServer := "8.8.8.8:53"
	switch transport {
	case "udp4":
		c.Net = "udp4"
	case "udp6":
		c.Net = "udp6"
		dnsServer = "[2001:4860:4860::8888]:53"
	default:
		return nil, fmt.Errorf("unsupported transport: %s", transport)
	}

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), qtype)
	m.RecursionDesired = true

	// Prefer a resolver from /etc/resolv.conf if it matches the requested family.
	config, err := dns.ClientConfigFromFile("/etc/resolv.conf")
	if err == nil && len(config.Servers) > 0 {
		for _, server := range config.Servers {
			candidate := net.JoinHostPort(server, config.Port)
			if _, resolveErr := net.ResolveUDPAddr(c.Net, candidate); resolveErr == nil {
				dnsServer = candidate
				break
			}
		}
	}

	resp, _, err := c.Exchange(m, dnsServer)
	if err != nil {
		return nil, err
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

// // Handler for MongoDB operations
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
	log.Printf("  GET /dns/a?domain=<domain>&transport=<udp4|udp6>")
	log.Printf("  GET /dns/aaaa?domain=<domain>&transport=<udp4|udp6>")
	log.Printf("  GET /dns/cname?domain=<domain>&transport=<udp4|udp6>")
	log.Printf("  GET /dns/txt?domain=<domain>&transport=<udp4|udp6>")
	log.Printf("  GET /dns/mx?domain=<domain>&transport=<udp4|udp6>")
	log.Printf("  GET /dns/srv?service=<service>&proto=<proto>&name=<name>&transport=<udp4|udp6>")
	log.Printf("  GET /mongodb?uri=<mongodb-srv-uri>")
	log.Printf("  GET /health")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatal(err)
	}
}
