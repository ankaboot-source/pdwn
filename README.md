# Personal Data Detector

Desktop application to detect personal and sensitive data in user folders. Helps identify and manage files containing sensitive information.

## Features

### Data Detection
- **Personal Data**: Email addresses, phone numbers, postal addresses, dates of birth
- **Financial Data**: IBAN bank account numbers, credit card numbers
- **Technical Secrets**: API keys, tokens, passwords, private keys, database connection strings
- **Cloud Credentials**: AWS, Azure, GCP service accounts and API keys
- **Identity Documents**: Government IDs (NIR for France, DNI/NIE for Spain)
- **Custom Detectors**: Define your own detection rules with regex patterns

### Scanning
- Initial full scan of watched directories
- Real-time file system watching for new/modified files
- Configurable file size limits and depth limits
- Skip hidden files (Unix) and temporary files
- Scan progress tracking with cancellation support

### User Interface
- Multi-language support: English, French, Spanish, German, Arabic
- Risk-based filtering (Critical, High, Medium, Low)
- Type-based filtering with multi-select dropdowns
- Sort by risk, date, or type
- Detailed report view with redacted examples
- Keyboard navigation and accessibility

### Actions
- Mark files as ignored
- Delete files to system trash
- Open file location in file manager
- System tray integration with quick actions
- Desktop notifications for new alerts and reminders

### Customization
- Watch multiple directories
- Configurable reminder schedules (24h, 7 days, 30 days)
- Custom detection rules with risk levels
- Locale-based default custom detectors (NIR for French, DNI/NIE for Spanish)

## Supported File Types

- **Documents**: PDF, Word, Excel, PowerPoint, Text files
- **Archives**: ZIP files (with weak encryption detection)
- **Images**: PNG, JPG, WebP (with optional OCR)
- **Configuration**: JSON, YAML, CSV, INI

## Installation

### Linux (.AppImage)

The application can be built as an AppImage for easy distribution:

```bash
# Install dependencies (if not already installed)
bun install

# Build the application
bun tauri build

# Find the built AppImage in:
# src-tauri/target/release/bundle/appimage/

# Make executable and run
chmod +x src-tauri/target/release/bundle/appimage/personal-data-detector-desktop_0.1.0_amd64.AppImage
./src-tauri/target/release/bundle/appimage/personal-data-detector-desktop_0.1.0_amd64.AppImage
```

Or use the AppImage as a portable application.

### Windows (.msi)

Double-click the installer to install the application. The MSI installer supports:
- Per-machine installation
- Silent installation for enterprise deployment

### Development

```bash
# Install dependencies
bun install

# Run in development mode
bun tauri dev

# Build for production (creates AppImage and other bundles)
bun tauri build
```

## Requirements

- **Runtime**: WebView2 (Windows), WebKitGTK (Linux)
- **Minimum OS**: Windows 10, Ubuntu 20.04 or equivalent
- **Disk Space**: ~50MB for application files

## Privacy

- All scanning is performed locally on your machine
- No data is sent to external servers
- Settings and detection rules are stored locally

## License

AGPL-3.0-only
