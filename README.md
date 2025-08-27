# Ferri - Bug Bounty Pipeline Tool

![Go](https://img.shields.io/badge/Go-1.18+-00ADD8?style=for-the-badge&logo=go)
![SQLite](https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

Ferri is a modular Go application designed to streamline bug bounty reconnaissance workflows by automatically processing and organizing reconnaissance data from various security tools into a structured SQLite database.

## 🚀 Features

- **Automated Data Processing**: Ingests output from popular reconnaissance tools
- **Smart Organization**: Automatically categorizes targets by program and type
- **Tool Detection**: Auto-detects common security tools (Subfinder, Amass, httpx, Nuclei, etc.)
- **Modular Architecture**: Easy to extend with new tools and features
- **SQLite Backend**: Lightweight, file-based database for portability
- **Cross-Platform**: Works on Windows, macOS, and Linux

## 📋 Supported Tools

Ferri currently supports processing output from:

- **Subdomain Discovery**: Subfinder, Amass, Assetfinder
- **HTTP Probing**: httpx
- **Vulnerability Scanning**: Nuclei
- **Archive Discovery**: Waybackurls, Gau
- **Fuzzing**: FFuf, Gobuster

## 🏗️ Architecture

```
ferri/
├── main.go                 # Entry point
├── database/               # Database connection and schema management
├── models/                 # Data models and repository patterns
├── utils/                  # Utility functions
└── processors/             # Business logic processors
```

## 📦 Installation

### Prerequisites

- Go 1.18 or higher
- Git

### Building from Source

```bash
# Clone the repository
git clone https://github.com/0xjson/ferri.git
cd ferri

# Build the application
go build -o ferri main.go

# Make it executable (Unix-like systems)
chmod +x ferri
```

### Using Go Install

```bash
go install github.com/0xjson/ferri@latest
```

## 🚦 Usage

### Basic Usage

```bash
# Process subdomain enumeration results
subfinder -d example.com | ferri

# Process URLs from a file
cat urls.txt | ferri

# Process live host results
echo "https://example.com" | ferri
```

### Database Location

By default, Ferri stores data in:
```
~/bugbounty/db/bounty.db
```

You can modify this path by setting the `DB_PATH` environment variable:

```bash
export DB_PATH="/path/to/your/database.db"
```

### Initial Setup

When you first run Ferri without input, it will create and initialize the database:

```bash
ferri
```

Output:
```
📭 No input provided via stdin
💾 Ensuring database exists: /home/user/bugbounty/db/bounty.db
✅ Database is ready for use
💡 Usage: echo 'example.com' | ferri
💡 Usage: subfinder -d example.com | ferri
```

## 🗄️ Database Schema

Ferri organizes data into four main tables:

1. **Programs**: Bug bounty programs and their scope
2. **Targets**: Individual targets (domains, subdomains, URLs)
3. **Recon Data**: Raw reconnaissance data from tools
4. **Findings**: Security vulnerabilities and findings

## 🔧 Extending Ferri

### Adding New Tool Support

1. Add tool pattern in `utils/detection.go`:
```go
"newtool": regexp.MustCompile(`newtool|pattern`),
```

2. Create processor functions in the appropriate package

### Adding New Data Processors

1. Create new functions in the `processors/` package
2. Follow the repository pattern in `models/` for database operations
3. Update main.go to handle new data types

### Custom Database Location

Modify the database path by setting the environment variable:

```bash
export FERRI_DB_PATH="/custom/path/to/database.db"
```

## 📊 Example Workflow

```bash
# 1. Discover subdomains
subfinder -d example.com -silent | ferri

# 2. Probe for live hosts
subfinder -d example.com -silent | httpx -silent | ferri

# 3. Scan for vulnerabilities
subfinder -d example.com -silent | httpx -silent | nuclei -t ~/nuclei-templates/ | ferri

# 4. Analyze results with SQL queries
sqlite3 ~/bugbounty/db/bounty.db "SELECT * FROM targets WHERE alive = 1;"
```

## 🤝 Contributing

We welcome contributions! Please feel free to submit pull requests, open issues, or suggest new features.

### Development Setup

1. Fork the repository
2. Clone your fork: `git clone https://github.com/0xjson/ferri.git`
3. Create a feature branch: `git checkout -b feature/amazing-feature`
4. Make your changes and test thoroughly
5. Commit your changes: `git commit -m 'Add amazing feature'`
6. Push to the branch: `git push origin feature/amazing-feature`
7. Open a pull request

### Testing

```bash
# Run basic tests
go test ./...

# Test with example data
echo "example.com" | go run main.go
```

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Inspired by various bug bounty workflow tools
- Built with the amazing Go programming language
- Uses the [go-sqlite3](https://github.com/mattn/go-sqlite3) driver

## 📮 Support

If you have any questions or need help:

1. Check the [Issues](https://github.com/0xjson/ferri/issues) page
2. Create a new issue if your problem isn't already documented

## 🚧 Roadmap

- [ ] Web interface for data visualization
- [ ] API endpoints for remote access
- [ ] Plugin system for custom tool integrations
- [ ] Advanced filtering and search capabilities
- [ ] Report generation functionality
- [ ] Integration with popular bug bounty platforms

---

⭐ **If you find Ferri useful, please give it a star on GitHub!**
