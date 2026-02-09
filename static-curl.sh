#!/bin/bash

# Static DNS API Server Test Commands
# Pure curl commands with no dynamic fields

echo "===== Testing DNS API Server ====="
echo ""

# Health Check
echo "1. Health Check:"
curl -s "http://localhost:8086/health" | jq
echo ""

# A Record over UDP4
echo "2. A Record Query over UDP4 (google.com):"
curl -s "http://localhost:8086/dns/a?domain=google.com&transport=udp4" | jq
echo ""

# A Record over UDP6 (real IPv6 transport)
echo "3. A Record Query over UDP6 (google.com):"
curl -s "http://localhost:8086/dns/a?domain=google.com&transport=udp6" | jq
echo ""

# AAAA Record over UDP6
echo "4. AAAA Record Query over UDP6 (google.com):"
curl -s "http://localhost:8086/dns/aaaa?domain=google.com&transport=udp6" | jq
echo ""

# CNAME Record
echo "5. CNAME Record Query (www.github.com):"
curl -s "http://localhost:8086/dns/cname?domain=www.github.com&transport=udp4" | jq
echo ""

# TXT Record
echo "6. TXT Record Query (google.com):"
curl -s "http://localhost:8086/dns/txt?domain=google.com&transport=udp4" | jq
echo ""

# MX Record
echo "7. MX Record Query (gmail.com):"
curl -s "http://localhost:8086/dns/mx?domain=gmail.com&transport=udp4" | jq
echo ""

# SRV Record
echo "8. SRV Record Query (_mongodb._tcp.cluster0.sjlpojg.mongodb.net):"
curl -s "http://localhost:8086/dns/srv?service=mongodb&proto=tcp&name=cluster0.sjlpojg.mongodb.net&transport=udp4" | jq
echo ""

# MongoDB Test
# echo "8. MongoDB Test (query existing documents):"
# curl -s "http://localhost:8086/mongodb?uri=" | jq
# echo ""

echo "===== All tests completed ====="
