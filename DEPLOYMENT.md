# CipherChat Deployment (Free Tier)

## Architecture
- Frontend: Cloudflare Pages (static HTML)
- Backend: Render Web Service (FastAPI)
- Database: Supabase Postgres (free tier)

## 1) Deploy Database (Supabase)
1. Create a new Supabase project.
2. Open Project Settings > Database and copy the connection string.
3. Use the transaction pooler or direct connection URL. For SQLAlchemy + psycopg2, use this format:
   - `postgresql+psycopg2://USER:PASSWORD@HOST:PORT/DBNAME`

## 2) Deploy Backend (Render)
1. Push this repo to GitHub.
2. In Render, create a new Web Service from the repo.
3. Render can auto-detect `render.yaml`, or configure manually:
   - Build command: `pip install -r requirements.txt`
   - Start command: `uvicorn main:app --host 0.0.0.0 --port $PORT`
4. Set environment variables:
   - `DATABASE_URL` = your Supabase SQLAlchemy URL
   - `SECRET_KEY` = any long random string
   - `FRONTEND_ORIGINS` = `https://your-frontend.pages.dev`
   - `ALLOW_DEV_OTP_FALLBACK` = `true` (set `false` in production after OTP providers are configured)
5. Optional OTP providers:
   - Email: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM`
   - SMS: `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM_NUMBER`

## 3) Deploy Frontend (Cloudflare Pages)
1. Create a Cloudflare Pages project connected to your GitHub repo.
2. Use:
   - Build command: (empty)
   - Build output directory: `/`
3. Ensure `_redirects` is included in deployment.
4. Open your Pages URL. On first load, app prompts for backend API URL.
   - Enter your Render URL, for example: `https://cipherchat-api.onrender.com`
   - This is saved to browser localStorage as `api_base_url`.

## 4) Go-live Checklist
1. Backend `/health` returns `{ "status": "ok" }`.
2. Register a user from frontend.
3. Login via OTP (dev fallback shows OTP if providers are not configured).
4. Open chat, send messages, verify message history.
5. Update profile photo and verify it appears in contacts and chat header.

## 5) Post-deploy Hardening
1. Set `ALLOW_DEV_OTP_FALLBACK=false`.
2. Configure real SMTP/Twilio credentials.
3. Rotate `SECRET_KEY` if previously shared.
4. Restrict `FRONTEND_ORIGINS` to your exact Pages domain.
