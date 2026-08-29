# Advanced React ChatFlow

Production-oriented React + Vite + Express + Socket.IO + PostgreSQL chat app for Render.

## Included
- JWT registration/login
- One-to-one conversations
- Real-time Socket.IO messaging
- Online/typing indicator
- Search users
- File uploads through Cloudinary
- PostgreSQL persistence
- Responsive mobile UI
- Message edit/delete API endpoints
- Render Blueprint (`render.yaml`)
- Environment variable template

## Render deployment
1. Create a PostgreSQL database on Render and copy its internal/external connection string.
2. Push this project to GitHub.
3. In Render choose **New > Blueprint** and select the repository.
4. Set `DATABASE_URL`, `JWT_SECRET`, and Cloudinary variables in the service environment.
5. Deploy. The build installs both client/server dependencies and builds React; Express serves `client/dist`.

## Local
Copy `.env.example` to `server/.env`, fill values, then run `npm run build && npm start` from the root. For frontend development use `npm --prefix client run dev`.
