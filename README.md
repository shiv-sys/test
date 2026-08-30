# ChatFlow – Render deployment

This version fixes the login screen/session initialization and real-time presence state.

## Render
- Build: `npm install && npm run build`
- Start: `npm start`
- Health: `/api/health`

Required environment variables:
- `DATABASE_URL`
- `JWT_SECRET`
- `CLOUDINARY_CLOUD_NAME`
- `CLOUDINARY_API_KEY`
- `CLOUDINARY_API_SECRET`

If a previous deployment left an old browser token, the app now automatically clears an invalid session and returns to the login screen.
