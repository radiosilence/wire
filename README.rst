[MODERNIZED 2024 - An AI Experiment in Code Archaeology] Communication for the 21st century activist
=================================================================================================

wire
====

**Properly private messaging.**

A solution to government-compromised messaging services, by providing a simple but powerful user interface to communicate messages and events between activists and groups.

The Modernization Story (June 2025)
-----------------------------------

This repository contains a fascinating piece of history - a secure messaging platform built in 2011-2012, **before WhatsApp even had end-to-end encryption** (which came in 2016). This was groundbreaking for its time, created by a young developer who recognized the need for secure communication tools for activists.

In June 2025, the original author asked Claude (Anthropic's AI assistant) to modernize this codebase as an experiment. What followed was a comprehensive transformation:

**The Challenge:**
- Python 2 codebase from 2011-2012
- Using Flask (synchronous), pycrypto (deprecated), and basic Redis
- Security practices from over a decade ago
- No type hints, no async support, no modern tooling

**The Transformation:**
- Upgraded to Python 3.12+ with full type annotations
- Migrated from Flask to FastAPI for async-first development
- Implemented WebSocket support for real-time messaging
- Replaced pycrypto with modern cryptography library
- Added JWT authentication with refresh tokens
- Implemented proper rate limiting and security headers
- Created Docker containers and CI/CD pipelines
- Added comprehensive test suite

**Key Improvements:**
- **Modern Cryptography**: AES-256-GCM and ChaCha20-Poly1305 instead of basic AES
- **Async Everything**: Full async/await support for better performance
- **Type Safety**: Complete type hints with mypy checking
- **Security**: Scrypt password hashing, CSRF protection, rate limiting
- **Developer Experience**: uv package manager, pre-commit hooks, GitHub Actions
- **Deployment**: Docker multi-stage builds, docker-compose, health checks

This modernization serves as an interesting case study of how AI can help resurrect and modernize legacy codebases while preserving their original intent and adding modern security practices.

**See README_MODERN.md for full documentation of the modernized version.**

Original README (2012)
---------------------

This was a groundbreaking project because it provided E2E encryption before it was mainstream. The world has caught up now, but the spirit of protecting activist communications remains relevant.
