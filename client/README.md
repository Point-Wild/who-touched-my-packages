# Who Touched My Packages - React Client

This is the React-based web client for the Who Touched My Packages security audit report viewer.

## Architecture

- **Framework**: React 19 with TypeScript
- **Build Tool**: Vite
- **Editor**: Monaco Editor for code viewing
- **Styling**: CSS with custom design system

## Development

```bash
# Install dependencies
bun install

# Start development server
bun run dev

# Build for production
bun run build
```

## Components

- **App.tsx**: Main application component with tab navigation
- **OverviewTab.tsx**: Summary statistics and vulnerability overview
- **VulnerabilitiesTab.tsx**: Detailed vulnerability table with search/filter
- **DependenciesTab.tsx**: All dependencies with vulnerability status
- **PinningTab.tsx**: Non-pinned dependencies viewer with Monaco editor

## API Endpoints

The client expects the following API endpoints from the static server:

- `GET /api/data` - Returns the complete report data (ReportData JSON)
- `GET /api/file?path=<filepath>` - Returns the content of a dependency file

## Building

The client is automatically built when you run `bun run build` in the root project directory. The built files are placed in `client/dist/` and served by the Node.js static server.
