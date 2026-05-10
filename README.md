# express-mitm

MITM proxy backend with a Wails desktop shell.

## Requirements

- Go 1.26.2 or newer
- Node.js 18 or newer
- Wails CLI 2.12.0 or newer

## Desktop App

```bash
wails dev
```

The React + TypeScript frontend lives in `frontend/` and talks to the existing Go backend through Wails.

## Build

```bash
wails build -nopackage
```

## CLI Backend

```bash
go run ./cmd/express-mitm
```

## Test

```bash
go test ./...
```
