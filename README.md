# DNS API Server

A simple Go API server that provides DNS query endpoints for various record types.

## Features

- **A Records**: Query IPv4 addresses
- **AAAA Records**: Query IPv6 addresses
- **TXT Records**: Query text records
- **MX Records**: Query mail exchange records
- **SRV Records**: Query service records

## Running the Server

```bash
go run main.go
```

The server will start on port `8086`.

## API Endpoints

### A Record over UDP4 (IPv4 transport)
```bash
curl "http://localhost:8086/dns/a?domain=google.com&transport=udp4"
```

### A Record over UDP6 (IPv6 transport)
```bash
curl "http://localhost:8086/dns/a?domain=google.com&transport=udp6"
```

### AAAA Record over UDP6 (IPv6 transport)
```bash
curl "http://localhost:8086/dns/aaaa?domain=google.com&transport=udp6"
```

### TXT Record
```bash
curl "http://localhost:8086/dns/txt?domain=google.com&transport=udp4"
```

### MX Record
```bash
curl "http://localhost:8086/dns/mx?domain=google.com&transport=udp4"
```

### SRV Record
```bash
curl "http://localhost:8086/dns/srv?service=xmpp-server&proto=tcp&name=gmail.com&transport=udp4"
```

### Health Check
```bash
curl "http://localhost:8086/health"
```

`transport` can be `udp4` or `udp6`. If omitted, the API defaults to `udp4`.

## Example Responses

### A Record Response
```json
{
  "domain": "google.com",
  "type": "A",
  "records": [
    "142.250.185.46"
  ]
}
```

### MX Record Response
```json
{
  "domain": "google.com",
  "type": "MX",
  "records": [
    {
      "host": "smtp.google.com.",
      "priority": 10
    }
  ]
}
```

### SRV Record Response
```json
{
  "domain": "_xmpp-server._tcp.gmail.com",
  "type": "SRV",
  "records": [
    {
      "target": "xmpp-server.l.google.com.",
      "port": 5269,
      "priority": 5,
      "weight": 0
    }
  ]
}
```
