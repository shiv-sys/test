# ChatFlow v10

Render Free compatible React + Express + Socket.IO chat app.

## Render
Build: `npm install && npm run build`
Start: `npm start`
Health: `/api/health`

Set these environment variables in Render:
- `DATABASE_URL`
- `JWT_SECRET`
- `CLOUDINARY_CLOUD_NAME` (optional for uploads)
- `CLOUDINARY_API_KEY` (optional for uploads)
- `CLOUDINARY_API_SECRET` (optional for uploads)

## v10 fixes
- Reworked conversation loading to avoid the PostgreSQL `syntax error at or near "FROM"` caused by complex nested conversation SQL.
- Direct user -> conversation creation is transaction-safe and duplicate-safe.
- Every `/api/*` failure returns JSON, never the React HTML shell.
- Active Now presence includes user profile data and real-time online/offline updates.
- Clicking an active or searched user opens the conversation immediately.
- Messages are loaded and the conversation is marked read.
- Added read timestamps and basic double-check display for your own read messages.
- Added `/api/diagnostics/schema` for authenticated database structure diagnostics without exposing credentials.
- Added safer registration/login compatibility for mixed legacy `users` schemas.
- Added last-seen timestamp maintenance.
