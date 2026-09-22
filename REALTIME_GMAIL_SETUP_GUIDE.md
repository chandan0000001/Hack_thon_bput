# 🛡️ CyberGuard: Real-Time Gmail Setup Guide

This guide walks you through setting up **CyberGuard Real-Time Gmail Auto-Scanning and Automated Quarantine** from start to finish.

Written in simple, plain English with copy-pasteable commands and step-by-step instructions.

---

## 🎯 How It Works in 30 Seconds

```
[Attacker Sends Email]
          │
          ▼
   [Your Gmail Inbox]
          │
          ▼  (Instant Google Pub/Sub Push Alert)
[Public Cloudflare HTTPS Tunnel]
          │
          ▼
 [CyberGuard Webhook (/api/v1/webhooks/gmail)]
          │
          ▼
   [Redis Job Queue]
          │
          ├─► [gmail_worker]  --> Fetches new email via Gmail API
          │
          └─► [email_worker]  --> Runs AI / ML Phishing Detection
                                       │
                      ┌────────────────┴────────────────┐
                      ▼                                 ▼
               [Clean Email]                     [Phishing Threat]
              (Remains in Inbox)                        │
                                                        ├─► Moves email to "CYBERGUARD-Quarantine"
                                                        ├─► Creates Gmail Filter to block sender
                                                        └─► Logs incident in CyberGuard SOC Dashboard
```

1. An email arrives in your Gmail.
2. Google instantly notifies CyberGuard via **Google Cloud Pub/Sub**.
3. CyberGuard's AI engine analyzes the email content, links, and headers in real time.
4. If a threat is detected, CyberGuard **automatically pulls the email out of your inbox** into a quarantine folder and **blocks the attacker in Gmail**.

---

## 🗺️ Integration Architecture (Visual Overview)

The setup below wires together three independent integrations: **OAuth 2.0** (mailbox access), **Cloud Pub/Sub** (push notifications), and the **Redis/Arq pipeline** (processing). Each diagram shows one.

### 1. OAuth 2.0 Mailbox Connection Flow

```mermaid
sequenceDiagram
    autonumber
    participant U as You (Browser)
    participant FE as CyberGuard UI<br/>/email-connectors
    participant API as FastAPI Backend
    participant G as Google OAuth 2.0

    U->>FE: Click "Connect Gmail Mailbox"
    FE->>API: POST /api/v1/connectors/gmail/authorize
    API->>API: Create single-use state row<br/>(connector_oauth_states, TTL 600 s)
    API-->>U: Redirect to Google consent screen
    U->>G: Sign in + approve scopes<br/>(gmail.modify · gmail.settings.basic)
    G->>API: GET /connectors/gmail/callback?code=...&state=...
    API->>API: Atomic state consumption<br/>(single-use, service-role helper)
    API->>G: Exchange code → access/refresh tokens
    API->>API: Encrypt tokens (Fernet, CONNECTOR_TOKEN_KEY)<br/>store in email_connector_accounts
    API-->>U: Redirect to /email-connectors<br/>(green "Connected" badge)
    Note over API: Plaintext tokens never leave the backend.<br/>The OAuth callback carries only a safe status — never a bearer token.
```

### 2. Pub/Sub Permission Chain (Who May Publish)

```mermaid
flowchart LR
    Mail["Gmail mailbox<br/>new message"] -->|"Gmail push service<br/>gmail-api-push@system.gserviceaccount.com"| IAM{"Is that service account<br/>granted roles/pubsub.publisher<br/>on YOUR topic?"}
    IAM -->|"No — default state"| Dropped["❌ Notification silently never published<br/>(most common setup failure)"]
    IAM -->|"Yes — Step 3 of this guide"| Topic["Pub/Sub topic<br/>cyberguard-gmail"]
    Topic --> Sub["Push subscription<br/>cyberguard-gmail-sub"]
    Sub -->|"HTTPS POST + verification token"| WH["CyberGuard webhook<br/>/api/v1/webhooks/gmail"]
    WH -->|"HTTP 200 <50 ms"| Sub

    style Dropped fill:#3b1a1a,stroke:#ef4444,color:#fafafa
```

### 3. End-to-End Component Interaction

```mermaid
flowchart TB
    subgraph Google["Google Cloud"]
        GM["Gmail API<br/>history.list · watch · modify"]
        PS["Cloud Pub/Sub"]
    end

    subgraph CG["CyberGuard"]
        WH["Thin Webhook (<50 ms)"]
        Q[("Redis / Arq")]
        GW["gmail-worker"]
        EW["email-worker"]
        SW["scheduler-worker"]
        DB[("PostgreSQL + RLS")]
        SOAR["SOAR Enforcement<br/>(quarantine + sender block)"]
        UI["SOC Dashboard<br/>/quarantine · LIVE pill"]
    end

    GM -->|push on delivery| PS --> WH --> Q
    Q --> GW -->|delta discovery| GM
    GW --> Q --> EW -->|fetch + ML analysis| GM
    EW --> DB -->|realtime CDC| UI
    EW -->|"threat verdict"| SOAR -->|label move + filter| GM
    SW -->|"renew watch 4× daily<br/>reconcile 2× hourly"| GM
```

---

## 📋 What You Need (Prerequisites)

Before you begin, ensure you have:
1. A **Google Account** (to access Google Cloud Console and to protect your mailbox).
2. **Python 3.11+** and [`uv`](https://docs.astral.sh/uv/) package manager installed.
3. **Node.js 18+** and `npm` installed.
4. **Redis** running locally (or via Docker) for background job queues.
5. **PostgreSQL** running (or Supabase local/cloud).
6. [`cloudflared`](https://github.com/cloudflare/cloudflared) installed (or `ngrok`) to provide a public HTTPS tunnel for Google's webhook.

---

## 🚀 Step-by-Step Setup Instructions

---

### Step 1: Create a Google Cloud Project & Enable APIs

1. Open your browser and go to the [Google Cloud Console](https://console.cloud.google.com/).
2. Log in with your Google account.
3. In the top bar, click the project selector dropdown and click **"New Project"**.
   - Project Name: `cyberguard-security` (or any name you prefer).
   - Click **Create**.
4. Make sure your newly created project is selected in the top bar.
5. In the top search bar, search for **Gmail API** and click **Enable**.
6. In the top search bar, search for **Cloud Pub/Sub API** and click **Enable**.
7. Note down your **Project ID** (e.g. `project-49d98b0c-15ed-4801-8f4` or `cyberguard-security-123456`). You can find this on the Cloud Console Dashboard.

---

### Step 2: Configure OAuth Consent Screen & Credentials

CyberGuard connects to Gmail using standard OAuth 2.0 so you can safely grant permission to monitor your inbox and manage threat filters.

#### 1. OAuth Consent Screen
1. In the left navigation menu, go to **APIs & Services** > **OAuth consent screen**.
2. Select **External** and click **Create**.
3. Fill in the required fields:
   - **App name**: `CyberGuard SOAR`
   - **User support email**: Your email address.
   - **Developer contact information**: Your email address.
   - Click **Save and Continue**.
4. **Scopes**:
   - Click **Add or Remove Scopes**.
   - Search and select these scopes:
     - `https://www.googleapis.com/auth/gmail.modify` *(Allows reading emails and moving threats to Quarantine)*
     - `https://www.googleapis.com/auth/gmail.settings.basic` *(Allows creating filters to block malicious senders)*
     - `openid`
     - `.../auth/userinfo.email`
     - `.../auth/userinfo.profile`
   - Click **Update**, then **Save and Continue**.
5. **Test Users**:
   - Click **Add Users**.
   - Enter the Gmail address of the inbox you want to protect (e.g., `your-name@gmail.com`).
   - Click **Add**, then **Save and Continue**.
   - Click **Back to Dashboard**.

#### 2. Create OAuth 2.0 Client ID
1. In the left menu, click **Credentials**.
2. Click **+ Create Credentials** > **OAuth client ID**.
3. Application type: Select **Web application**.
4. Name: `CyberGuard Web App`.
5. Under **Authorized redirect URIs**, click **+ Add URI** and add:
   - `http://localhost:8000/api/v1/connectors/gmail/callback`
   - `http://127.0.0.1:8000/api/v1/connectors/gmail/callback`
6. Click **Create**.
7. A dialog will appear with your **Client ID** and **Client Secret**. Copy both values — you will need them in your `.env` file!

#### Why a dedicated OAuth client (permission boundaries)

CyberGuard deliberately uses **two separate Google/Supabase identities** with
non-overlapping purposes — a design decision recorded in
[DECISIONS.md](DECISIONS.md):

```mermaid
flowchart TB
    subgraph Login["Login Identity (Supabase Auth Google IdP)"]
        L["Purpose: prove who you are<br/>Scope: your CyberGuard account session<br/>Token custody: browser (Supabase JS client)"]
    end

    subgraph Mailbox["Mailbox Identity (CyberGuard's own OAuth client)"]
        M["Purpose: read + act on your mailbox<br/>Scope: gmail.modify · gmail.settings.basic<br/>Token custody: backend Fernet vault only"]
    end

    L -.->|"never interchangeable"| M
```

The requested Gmail scopes map directly to enforcement capabilities:

| Scope | Grants | Used For |
|---|---|---|
| `gmail.modify` | Read messages, add/remove labels (incl. INBOX) | Scanning, `CYBERGUARD-Quarantine` moves, releases |
| `gmail.settings.basic` | Manage basic mail settings | Creating sender-block filter rules |
| `openid` / `userinfo.email` / `userinfo.profile` | Identity | Matching the mailbox to your CyberGuard account |

---

### Step 3: Create the Google Cloud Pub/Sub Topic & Grant Permissions

Google Pub/Sub is the messaging bus Google uses to alert CyberGuard whenever a new email arrives.

#### 1. Create Topic
1. In Google Cloud Console, search for **Pub/Sub** or go to **Pub/Sub** > **Topics**.
2. Click **Create Topic**.
3. Topic ID: Enter `cyberguard-gmail`.
4. Leave other settings as default and click **Create**.
5. Note your full topic path. It will look like:
   ```
   projects/<YOUR-PROJECT-ID>/topics/cyberguard-gmail
   ```

#### 2. Grant Gmail Permission to Publish to this Topic (CRITICAL STEP!)
By default, Google's internal Gmail push system is not allowed to publish messages to your topic unless you explicitly give it permission.

1. Click on your topic name `cyberguard-gmail` to open its details.
2. In the right-hand panel (or under the **Permissions** tab), click **Add Principal**.
3. In **New principals**, paste this exact Google service account:
   ```
   gmail-api-push@system.gserviceaccount.com
   ```
4. In **Select a role**, choose:
   **Pub/Sub** > **Pub/Sub Publisher** (`roles/pubsub.publisher`).
5. Click **Save**.

---

### Step 4: Start Your Public HTTPS Tunnel

Google Cloud Pub/Sub requires a publicly accessible HTTPS URL to deliver push notifications. When developing locally, we use Cloudflare Tunnel to expose our local FastAPI port `8000`.

#### Quick Option: Use the built-in helper script
From your repository root, run:
```bash
cd backend
uv run python scripts/setup_realtime_watch.py --start-tunnel
```

#### Manual Option: Run cloudflared directly
```bash
cloudflared tunnel --url http://127.0.0.1:8000
```

You will see output containing your active tunnel URL, for example:
```
https://arm-sword-pics-numeric.trycloudflare.com
```

Your public CyberGuard webhook URL is:
```
https://<YOUR-SUBDOMAIN>.trycloudflare.com/api/v1/webhooks/gmail
```

> 💡 **Keep this terminal running.** If you restart the tunnel, Cloudflare will assign a new URL, and you will simply update the Pub/Sub subscription endpoint in Step 5.

---

### Step 5: Create the Pub/Sub Push Subscription

Now connect your Pub/Sub topic to your CyberGuard webhook.

1. In Google Cloud Console, navigate to **Pub/Sub** > **Subscriptions**.
2. Click **Create Subscription**.
3. Fill in the fields:
   - **Subscription ID**: `cyberguard-gmail-sub`
   - **Select a Cloud Pub/Sub topic**: Select `projects/<YOUR-PROJECT-ID>/topics/cyberguard-gmail`
   - **Delivery type**: Select **Push**
   - **Endpoint URL**: Paste your public webhook URL from Step 4:
     ```
     https://<YOUR-SUBDOMAIN>.trycloudflare.com/api/v1/webhooks/gmail
     ```
   - **Subscription expiration**: Select **Never expire** (or 365 days)
   - **Acknowledgement deadline**: Change to **30 seconds**
   - **Retry policy**: Retry immediately
4. Leave other options as default and click **Create**.

---

### Step 6: Configure Environment Variables

#### 1. Backend (`backend/.env`)
Open `backend/.env` (or copy from `backend/.env.example`) and configure the following variables:

```ini
# Google OAuth Client (from Step 2)
GOOGLE_GMAIL_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_GMAIL_CLIENT_SECRET=your-client-secret
GOOGLE_GMAIL_REDIRECT_URI=http://localhost:8000/api/v1/connectors/gmail/callback
FRONTEND_CONNECTORS_URL=http://localhost:5173/email-connectors

# Google Pub/Sub Topic (from Step 3)
GMAIL_PUBSUB_TOPIC=projects/<YOUR-PROJECT-ID>/topics/cyberguard-gmail

# Encryption key for securing tokens at rest (generate one if empty)
# uv run python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
CONNECTOR_TOKEN_KEY=your-32-byte-fernet-key=
GMAIL_CONNECTOR_ENABLED=true

# Database & Redis
DATABASE_URL=postgresql+asyncpg://cyberguard_api:password@localhost:5432/cyberguard
REDIS_URL=redis://localhost:6379/0

# LLM Providers (Groq, Gemini, or OpenRouter for threat analysis)
GROQ_API_KEY=your-groq-api-key
GEMINI_API_KEY=your-gemini-api-key
```

#### 2. Frontend (`frontend/.env.local`)
Open `frontend/.env.local` and ensure:
```ini
VITE_API_BASE_URL=http://localhost:8000
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_ANON_KEY=your-supabase-anon-key
```

---

### Step 7: Launch All Services

To run CyberGuard with full real-time email scanning, start each of the following processes in separate terminal tabs:

#### 🖥️ Terminal 1: Public Tunnel
*(If not already running from Step 4)*
```bash
cd backend
uv run python scripts/setup_realtime_watch.py --start-tunnel
```

#### 🖥️ Terminal 2: FastAPI Backend
```bash
cd backend
uv run uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```
*Health check:* Visit `http://127.0.0.1:8000/api/v1/health` (should return `"status": "ok"`).

#### 🖥️ Terminal 3: Gmail Sync Worker
This worker receives Pub/Sub notification jobs and asks Gmail for changed message IDs.
```bash
cd backend
uv run python -m app.workers.gmail_worker
```

#### 🖥️ Terminal 4: Email ML Analysis Worker
This worker downloads message contents, runs ML phishing detection, and executes automated quarantine actions.
```bash
cd backend
uv run python -m app.workers.email_worker
```

#### 🖥️ Terminal 5: Scheduler Worker
This worker handles recurring tasks, including automatically renewing Gmail watches every 6 hours so your mailbox monitoring never expires.
```bash
cd backend
uv run python -m app.workers.scheduler_worker
```

#### 🖥️ Terminal 6: Frontend App
```bash
cd frontend
npm run dev
```
*Web App:* Visit `http://localhost:5173`.

---

### Step 8: Connect Your Gmail Mailbox & Activate Live Watch

Now you connect your inbox to CyberGuard!

1. Open your browser and navigate to:
   ```
   http://localhost:5173/email-connectors
   ```
2. Click the **"Connect Gmail Mailbox"** button.
3. A Google sign-in window will open. Select your Google account.
4. If Google displays a "Google hasn't verified this app" warning (normal during development/testing mode):
   - Click **Advanced**.
   - Click **Go to CyberGuard SOAR (unsafe)**.
5. Check all requested permissions (Read, compose, send, and modify emails; manage basic mail settings) and click **Continue**.
6. You will be redirected back to `http://localhost:5173/email-connectors`. You should see your email address listed with a green **"Connected"** badge.

#### Activate the Google Watch
To immediately register the real-time push hook with Google's API:
```bash
cd backend
uv run python scripts/setup_realtime_watch.py --watch
```
You will see output:
```
🔄 Calling Google Gmail watch() API for connected mailboxes...
Result: 1 renewed, 0 errors, 0 skipped.
```

#### Verify System Status Anytime
Run:
```bash
cd backend
uv run python scripts/setup_realtime_watch.py
```
This checks your Pub/Sub configuration, tunnel status, and connected mailboxes.

---

### Step 9: Test It Live!

Now let's test the entire pipeline to watch CyberGuard auto-detect and quarantine a phishing threat in real time.

#### Test Option A: Simulated Webhook (Fastest Check)
To test without sending an email:
```bash
cd backend
uv run python scripts/setup_realtime_watch.py --simulate
```
Watch the logs in Terminal 3 (`gmail_worker`) and Terminal 4 (`email_worker`) to confirm the webhook triggers the processing pipeline.

#### Test Option B: Live End-to-End Test (Real Phishing Detection)
1. Using a **different email account** (e.g. your personal account, a secondary test account, or Outlook/Yahoo):
2. Send an email to your protected Gmail address with a suspicious subject and body, for example:
   - **Subject**: `URGENT: Your account security has been compromised`
   - **Body**: `Dear customer, we detected unauthorized activity. Please verify your password immediately to prevent account suspension: http://secure-account-verification-login.com/reset-password`
3. Hit **Send**.
4. **Watch what happens automatically within 3 to 10 seconds**:
   - Google Pub/Sub sends a push alert to your Cloudflare tunnel.
   - Terminal 2 logs: `POST /api/v1/webhooks/gmail HTTP/1.1 200 OK`.
   - Terminal 3 (`gmail_worker`) fetches the new message history.
   - Terminal 4 (`email_worker`) evaluates the email with the ML model:
     ```
     INFO: Email analysis complete: id=... classification=phishing risk_score=0.92
     WARNING: Threat detected in email from attacker@example.com (score: 0.92) - executing automated quarantine
     INFO: Moving email to label CYBERGUARD-Quarantine and removing INBOX
     INFO: Created Gmail filter to block sender: attacker@example.com
     INFO: Logged quarantined item in cyberguard.quarantined_items
     ```
5. Check your Gmail inbox:
   - **The email is gone from your INBOX!**
   - Look at your Gmail folders on the left: you will find a label named **`CYBERGUARD-Quarantine`** containing the message.
6. Check the CyberGuard Web Interface:
   - Navigate to **`http://localhost:5173/quarantine`**: The email is listed with its risk score, phishing markers, and quarantined timestamp.
   - Navigate to **`http://localhost:5173/blocked-senders`**: The sender's email address is listed under Active Block Rules.

---

## 🛡️ Managing Quarantines, Blocks & Trusted Senders

CyberGuard provides full control over enforcement actions directly from the web interface:

### 1. The Quarantine Page (`/quarantine`)
- **Inspect**: View full details, headers, extracted links, and reasons why the AI classified the email as malicious.
- **Restore Email**: Removes the email from quarantine and moves it back to your Gmail `INBOX`.
- **Trust & Restore**: Restores the email to your inbox AND adds the sender to your **Trusted Senders** list so their future emails are never automatically quarantined.
- **Permanently Delete**: Purges the email completely from Gmail Trash.

### 2. The Blocked & Trusted Senders Page (`/blocked-senders`)
- **Active Block Rules**: Displays all sender addresses currently blocked by Gmail filters. You can click **Unblock** at any time to remove the filter in Gmail.
- **Trusted Senders (Allowlist)**: Displays senders you have marked as trusted.
  - Senders in this list are **exempted from automatic quarantine**.
  - If a trusted sender sends a suspicious email, CyberGuard logs the threat and flags a recommendation in the dashboard, but leaves the email in your inbox.
  - To resume auto-quarantining a sender, click **Untrust**.

---

## 🔧 Troubleshooting & Common Issues

| Issue | Cause | Solution |
|---|---|---|
| **Webhook returns 404 or connection refused** | The Cloudflare tunnel is not running or URL changed. | Run `uv run python scripts/setup_realtime_watch.py --start-tunnel`. If the URL changed, update the endpoint in Google Cloud Console > Pub/Sub > Subscriptions. |
| **Pub/Sub push notifications are not arriving** | Gmail service account lacks publisher permissions on the topic. | In Cloud Console > Pub/Sub > Topics > `cyberguard-gmail` > Permissions, ensure `gmail-api-push@system.gserviceaccount.com` has the **Pub/Sub Publisher** role. |
| **Email is received in Gmail but NOT quarantined** | 1. The sender is on your **Trusted Senders** list.<br>2. `email_worker` is not running.<br>3. Gmail watch expired. | 1. Check `/blocked-senders` and click **Untrust** if needed.<br>2. Ensure Terminal 4 (`email_worker`) is running.<br>3. Run `uv run python scripts/setup_realtime_watch.py --watch`. |
| **Google displays "Google hasn't verified this app" during OAuth** | The app is in "Testing" mode in Google Cloud Console. | Click **Advanced** > **Go to CyberGuard SOAR (unsafe)**. Make sure your email is added under "Test Users" in the OAuth consent screen. |
| **Google returns 403 Insufficient Scope** | Missing Gmail settings scope. | Ensure `https://www.googleapis.com/auth/gmail.settings.basic` is enabled in your OAuth consent screen and disconnect/reconnect your mailbox in `/email-connectors`. |
| **Manual filter deletion in Gmail causes error** | Filter was already deleted in Gmail UI. | Handled automatically: CyberGuard treats 404s as clean idempotent deletions and automatically clears the local record. |

---

## 📚 Architecture Reference Cheat Sheet

- **Webhook Endpoint**: `POST /api/v1/webhooks/gmail`
- **Watch Registration Service**: `app/services/gmail/watch_service.py`
- **Mailbox Connectors Service**: `app/services/connectors/oauth_service.py`
- **Quarantine Label**: `CYBERGUARD-Quarantine`
- **Setup & Diagnostics CLI**: `backend/scripts/setup_realtime_watch.py`
- **Automated Watch Renewal**: Handled every 6 hours by `app/workers/scheduler_worker.py`
- **Test Suite**: `cd backend && uv run pytest tests/ -k "gmail or connector or enforcement"`
