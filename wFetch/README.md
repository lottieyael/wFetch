# wFetch

A Windows system information tool built with Tauri and React.

## Features

- Display comprehensive system information (OS, CPU, Memory, GPU, Disk, Network)
- AI-powered system analysis using DeepSeek API
- Modern, responsive UI

## Setup

### Prerequisites

- Node.js and pnpm
- Rust toolchain
- Tauri CLI

### Installation

1. Clone the repository
2. Install dependencies:
   ```bash
   cd wFetch
   pnpm install
   ```

3. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Add your DeepSeek API key:
     ```
     DEEPSEEK_API_KEY=your-actual-api-key-here
     ```
   - Get your API key from [DeepSeek Platform](https://platform.deepseek.com/)

### Running

```bash
pnpm tauri dev
```

### Building

```bash
pnpm tauri build
```

After building, the installer will be located at:
- **Windows**: `src-tauri/target/release/bundle/msi/` (`.msi` installer) or `src-tauri/target/release/bundle/nsis/` (`.exe` installer)
- **macOS**: `src-tauri/target/release/bundle/dmg/` (`.dmg` file) or `src-tauri/target/release/bundle/macos/` (`.app` bundle)
- **Linux**: `src-tauri/target/release/bundle/deb/` (`.deb` package) or `src-tauri/target/release/bundle/appimage/` (`.AppImage` file)

## Environment Variables

- `DEEPSEEK_API_KEY`: Your DeepSeek API key (required for AI analysis feature)

## Note

The `.env` file is gitignored to keep your API key secure. Make sure to set it up locally before running the application.
