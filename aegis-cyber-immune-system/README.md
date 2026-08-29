# AEGIS - Autonomous Cyber Immune System

## Overview

**AEGIS** (Autonomous Enterprise-grade Genetic Immune System) is a next-generation autonomous cyber immune system designed for enterprise environments. It leverages AI/ML technologies to detect, analyze, and respond to cyber threats in real-time.

## Key Features

- **Real-time Threat Detection**: Advanced ML models for anomaly detection and threat classification
- **Knowledge Graph**: Neo4j-based graph database for IOC, CVE, and TTP correlation
- **Automated Response**: Playbook-driven automated remediation and incident response
- **Multi-format Data Ingestion**: Support for NetFlow, Syslog, CEF, STIX formats
- **Graph Neural Networks**: Deep learning on security knowledge graphs
- **Enterprise-grade**: Horizontal scalability, high availability, and fault tolerance

## Technology Stack

- **Backend**: Python 3.12 + FastAPI
- **AI/ML**: PyTorch, TensorFlow, Scikit-learn, NetworkX
- **Databases**: Neo4j (Graph), Elasticsearch (Logs), Redis (Cache), TimescaleDB (Time-series)
- **Messaging**: Apache Kafka
- **Infrastructure**: Docker, Kubernetes
- **Monitoring**: Prometheus, Grafana

## Installation

### Prerequisites

- Docker & Docker Compose
- Python 3.12+ (for local development)

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/your-org/aegis-cyber-immune-system.git
cd aegis-cyber-immune-system
```

2. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. **Start with Docker Compose**
```bash
docker-compose up -d
```

4. **Access the API documentation**
```
http://localhost:8000/docs
```

### Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
uvicorn src.api.main:app --reload

# Run tests
pytest

# Code quality checks
make lint
```

## Usage Examples

### Health Check
```bash
curl http://localhost:8000/health
```

### Get System Info
```bash
curl http://localhost:8000/api/v1/info
```

### Ingest Telemetry Data
```bash
curl -X POST http://localhost:8000/api/v1/telemetry/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "source_ip": "192.168.1.100",
    "destination_ip": "10.0.0.50",
    "source_port": 54321,
    "destination_port": 443,
    "protocol": "TCP",
    "bytes_sent": 1024,
    "bytes_received": 2048,
    "packets": 10
  }'
```

### Get Threat List
```bash
curl http://localhost:8000/api/v1/threats
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Basic health check |
| `/api/v1/health` | GET | API version health check |
| `/api/v1/info` | GET | System information |
| `/api/v1/telemetry/ingest` | POST | Ingest telemetry data |
| `/api/v1/telemetry` | GET | Retrieve telemetry data |
| `/api/v1/threats` | GET | List threats |
| `/api/v1/threats/{id}` | GET | Get threat details |
| `/api/v1/threats/analyze` | POST | AI-powered threat analysis |
| `/api/v1/analytics/dashboard` | GET | Security dashboard |
| `/api/v1/analytics/statistics` | GET | Security statistics |
| `/api/v1/analytics/graph` | GET | Knowledge graph visualization |

## Project Structure

```
aegis-cyber-immune-system/
├── config/          # Configuration files
├── src/             # Source code
│   ├── api/         # FastAPI routes and middleware
│   ├── core/        # Core utilities and config
│   ├── models/      # Pydantic data models
│   ├── ingestion/   # Data ingestion and parsers
│   ├── ai/          # AI/ML models and knowledge graph
│   ├── detection/   # Threat detection engine
│   └── response/    # Automated response system
├── tests/           # Test suites
├── docs/            # Documentation
└── scripts/         # Deployment and utility scripts
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md)
- [API Reference](docs/API.md)
- [Deployment Guide](docs/DEPLOYMENT.md)
- [Specification](docs/SPECIFICATION.md)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For questions and support, please open an issue on GitHub.

---

**Version**: 1.0.0  
**Status**: Development
