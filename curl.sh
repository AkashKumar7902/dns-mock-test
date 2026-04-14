#!/bin/bash

# DNS API Server Test Script
# Make sure the server is running: go run main.go

BASE_URL="http://localhost:8086"
NEGATIVE_DNS_DOMAIN="keploy-negative.invalid"

echo "===== Testing DNS API Server ====="
echo ""

# Health Check
echo "1. Health Check:"
curl -s "${BASE_URL}/health" | jq
echo ""

# A Record over UDP4
echo "2. A Record Query over UDP4 (google.com):"
curl -s "${BASE_URL}/dns/a?domain=google.com&transport=udp4" | jq
echo ""

# A Record over UDP6 (real IPv6 transport)
echo "3. A Record Query over UDP6 (google.com):"
curl -s "${BASE_URL}/dns/a?domain=google.com&transport=udp6" | jq
echo ""

# AAAA Record over UDP6
echo "4. AAAA Record Query over UDP6 (google.com):"
curl -s "${BASE_URL}/dns/aaaa?domain=google.com&transport=udp6" | jq
echo ""

# CNAME Record
echo "5. CNAME Record Query (www.github.com):"
curl -s "${BASE_URL}/dns/cname?domain=www.github.com&transport=udp4" | jq
echo ""

# TXT Record
echo "6. TXT Record Query (google.com):"
curl -s "${BASE_URL}/dns/txt?domain=google.com&transport=udp4" | jq
echo ""

# MX Record
echo "7. MX Record Query (gmail.com):"
curl -s "${BASE_URL}/dns/mx?domain=gmail.com&transport=udp4" | jq
echo ""

# SRV Record
echo "8. SRV Record Query (_mongodb._tcp.cluster0.sjlpojg.mongodb.net):"
curl -s "${BASE_URL}/dns/srv?service=mongodb&proto=tcp&name=cluster0.sjlpojg.mongodb.net&transport=udp4" | jq
echo ""

# Negative lookup
echo "9. Negative A Record Query over UDP4 (${NEGATIVE_DNS_DOMAIN}):"
negative_response=$(curl -s "${BASE_URL}/dns/a?domain=${NEGATIVE_DNS_DOMAIN}&transport=udp4")
echo "$negative_response" | jq

if ! echo "$negative_response" | jq -e '.error == "DNS query failed with code: 3"' >/dev/null; then
  echo "Expected NXDOMAIN response for ${NEGATIVE_DNS_DOMAIN}"
  exit 1
fi
echo ""

# # Error handling test
# echo "8. Error Test (missing domain parameter):"
# curl -s "${BASE_URL}/dns/a" | jq
# echo ""

# MongoDB Test
# echo "9. MongoDB Test (query existing documents):"
# curl -s "${BASE_URL}/mongodb?uri=" | jq
# echo ""

echo "===== All tests completed ====="
