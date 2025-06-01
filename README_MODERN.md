# Wire 2.0 - Secure Messaging Platform

A modern, async-first secure messaging platform with end-to-end encryption, built for activists and privacy-conscious users.

## 🚀 What's New in 2.0

- **Full async/await support** using Python 3.12+
- **FastAPI** for high-performance async API
- **WebSocket support** for real-time messaging
- **Modern cryptography** with AES-256-GCM and ChaCha20-Poly1305
- **Type hints** throughout the codebase
- **JWT-based authentication** with refresh tokens
- **Rate limiting** and security headers
- **Docker support** for easy deployment

## 🔐 Security Features

- **End-to-End Encryption**: All messages are encrypted using modern AEAD ciphers
- **Perfect Forward Secrecy**: Each message uses unique encryption keys
- **Password Security**: Scrypt-based password hashing with high iteration counts
- **2FA Support**: Optional two-factor authentication
- **Rate Limiting**: Protection against brute force attacks
- **Security Headers**: CSP, HSTS, and other security headers enabled
- **Input Validation**: Comprehensive validation using Pydantic

## 🛠 Technology Stack

- **Python 3.12+**: Modern Python with full type hints
- **FastAPI**: High-performance async web framework
- **Redis**: Data storage with async support
- **Uvicorn**: ASGI server with HTTP/2 support
- **Pydantic**: Data validation and settings management
- **Cryptography**: Modern cryptographic primitives
- **WebSockets**: Real-time bidirectional communication

## 📦 Installation

### Prerequisites

- Python 3.12 or higher
- Redis 7.0 or higher
- uv (recommended) or pip

### Using uv (Recommended)

```bash
# Install uv if you haven't already
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/yourusername/wire.git
cd wire

# Create virtual environment and install dependencies
uv venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
uv pip sync pyproject.toml
```

### Using mise for Python version management

```bash
# Install mise
curl https://mise.run | sh

# Install Python and dependencies
mise install
uv pip sync pyproject.toml
```

## 🚀 Running the Application

### Development Server

```bash
# Initialize the application
wire init

# Run the development server with auto-reload
wire run --reload

# Or specify host and port
wire run --host 0.0.0.0 --port 8000 --reload
```

### Production Server

```bash
# Run with multiple workers
wire serve --workers 4 --bind 0.0.0.0:8000

# Or use uvicorn directly
uvicorn wire.app:app --host 0.0.0.0 --port 8000 --workers 4
```

## 🔧 Configuration

Create a `.env` file in the project root:

```env
# Security
WIRE_SECRET_KEY=your-very-secure-secret-key-here
WIRE_ENVIRONMENT=production

# Redis
WIRE_REDIS_HOST=localhost
WIRE_REDIS_PORT=6379
WIRE_REDIS_PASSWORD=your-redis-password

# Security Settings
WIRE_SESSION_COOKIE_SECURE=true
WIRE_CSRF_ENABLED=true
WIRE_RATE_LIMIT_ENABLED=true

# Features
WIRE_ENABLE_FILE_SHARING=true
WIRE_ENABLE_GROUP_CHATS=true
WIRE_ENABLE_MESSAGE_REACTIONS=true
```

## 📡 API Documentation

When running in development mode, interactive API documentation is available at:

- Swagger UI: `http://localhost:8000/api/docs`
- ReDoc: `http://localhost:8000/api/redoc`

### Authentication

```bash
# Register a new user
curl -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "email": "alice@example.com", "password": "SecurePass123!"}'

# Login
curl -X POST http://localhost:8000/api/v1/auth/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=alice&password=SecurePass123!"
```

### WebSocket Connection

```javascript
// Connect to WebSocket for real-time messaging
const ws = new WebSocket('ws://localhost:8000/ws/alice');

ws.onmessage = (event) => {
  const message = JSON.parse(event.data);
  console.log('Received:', message);
};

// Send a message
ws.send(JSON.stringify({
  type: 'message',
  recipient: 'bob',
  content: 'Hello, Bob!'
}));
```

## 🧪 Testing

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=wire --cov-report=html

# Run specific test file
pytest tests/test_crypto.py

# Run tests in parallel
pytest -n auto
```

## 🐳 Docker Deployment

```bash
# Build the Docker image
docker build -t wire:latest .

# Run with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f
```

## 🛡️ Security Best Practices

1. **Always use HTTPS in production** - Set up TLS certificates
2. **Use strong secrets** - Generate with `wire security generate-secret`
3. **Enable 2FA** - Encourage users to enable two-factor authentication
4. **Regular updates** - Keep dependencies updated with `uv pip compile --upgrade`
5. **Monitor logs** - Set up proper logging and monitoring
6. **Backup data** - Regular Redis backups are essential

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Development Setup

```bash
# Install development dependencies
uv pip install -e ".[dev]"

# Set up pre-commit hooks
pre-commit install

# Run linting
ruff check wire/

# Run type checking
mypy wire/

# Format code
black wire/
```

## 📝 CLI Commands

```bash
# User management
wire user create --username alice --email alice@example.com
wire user list
wire user delete alice

# Database management
wire db info
wire db reset  # Warning: deletes all data!

# Security
wire security check
wire security generate-secret

# Development
wire run --reload
wire serve --workers 4
```

## 🚨 Troubleshooting

### Redis Connection Issues

```bash
# Check Redis is running
redis-cli ping

# Test connection with Wire settings
wire db info
```

### Performance Issues

1. Increase Redis connection pool size in `.env`
2. Add more Uvicorn workers: `wire serve --workers 8`
3. Enable Redis persistence for better reliability

### WebSocket Issues

1. Check firewall settings allow WebSocket connections
2. Ensure reverse proxy (if used) supports WebSocket upgrade
3. Check browser console for connection errors

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## ⚠️ Disclaimer

While Wire implements strong encryption and security measures, no system is 100% secure. Always assess your threat model and use additional security measures as appropriate for your use case.