# Contributing to CVE.ICU

Thank you for your interest in contributing to CVE.ICU! This document provides guidelines for contributing to this project.

## Code of Conduct

Be respectful and constructive in all interactions. We're all here to build better security tools.

## Getting Started

### Prerequisites

- Python 3.11+
- Git
- ~2GB disk space for cached data

### Development Setup

```bash
# Fork and clone the repository
git clone https://github.com/RogoLabs/cve.icu.git
cd cve.icu

# Install dependencies
pip install -r requirements.txt

# Run tests to verify setup
pytest tests/ -v

# Run a quick build (uses cached data if available)
python data/scripts/quick_build.py
```

## How to Contribute

### Reporting Issues

- Check existing issues before creating new ones
- Include steps to reproduce for bugs
- Provide context: Python version, OS, error messages

### Pull Requests

1. **Fork** the repository
2. **Create a branch** from `main`: `git checkout -b feature/your-feature`
3. **Make changes** following our code style
4. **Run tests**: `pytest tests/ -v`
5. **Commit** with clear messages: `git commit -m 'Add feature X'`
6. **Push** to your fork: `git push origin feature/your-feature`
7. **Open a PR** against `main`

### Code Style

- Follow PEP 8 for Python code
- Use type hints where helpful
- Add docstrings to functions and classes
- Keep functions focused and testable

### Testing

- Add tests for new functionality
- Ensure all tests pass before submitting PR
- Use pytest fixtures from `tests/conftest.py`

```bash
# Run all tests
pytest tests/ -v

# Run specific test file
pytest tests/test_build.py -v

# Run with coverage
pytest tests/ --cov=data --cov-report=html
```

### Documentation

- Update README.md for user-facing changes
- Update relevant docs/ files for technical changes
- Add inline comments for complex logic

## Project Structure

```
cve.icu/
├── build.py              # Main build script
├── data/                 # Analysis modules
│   ├── *_analysis.py     # Individual analyzers
│   ├── scripts/          # Utility scripts
│   └── cache/            # Downloaded data (gitignored)
├── templates/            # Jinja2 HTML templates
├── tests/                # pytest test suite
├── docs/                 # Documentation
└── web/                  # Generated output
```

## Priority Areas

We especially welcome contributions in:

1. **Test Coverage** - More edge cases and integration tests
2. **Performance** - Build time and data processing optimizations
3. **Visualizations** - New Chart.js visualizations
4. **Documentation** - Improved explanations and examples
5. **Accessibility** - Web accessibility improvements

## Questions?

- Open an issue for discussion
- Check [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for technical details
- Review [docs/ROADMAP.md](docs/ROADMAP.md) for project direction

---

**A [RogoLabs](https://rogolabs.net/) Project**
