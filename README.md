# Advanced ChatFlow — Render Ready

This version uses a **single root Vite + Express project** so Render builds from the repository root without needing a `client/` subdirectory.

## Render
- Runtime: Node
- Build command: `npm install && npm run build`
- Start command: `npm start`
- Health check: `/api/health`

### Required environment variables
`DATABASE_URL`, `JWT_SECRET`, `CLOUDINARY_CLOUD_NAME`, `CLOUDINARY_API_KEY`, `CLOUDINARY_API_SECRET`

Create a Render PostgreSQL database and use its connection string for `DATABASE_URL`.

## Local
```bash
npm install
npm run build
npm start
```
