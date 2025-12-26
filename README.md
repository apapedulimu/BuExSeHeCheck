# 🔎 BuExSeHeCheck  
**Burp Extension – Security Header Checker**

Burp Suite extension to analyze HTTP security headers with color-coded results and request/response context.

BuExSeHeCheck helps penetration testers and security engineers quickly analyze HTTP response security headers directly from Burp’s HTTP history, providing clear visibility into missing and misconfigured headers.

---

## ✨ Features

- 📤 **Send from HTTP History**
  - Right-click any request and select **“Send to Security Header Checker”**

- 🧾 **Request & Response Viewer**
  - Displays the exact HTTP request and response sent to the tool
  - View-only (non-editable)

- 🔍 **Security Header Analysis**
  - Checks the following headers:
    - X-Frame-Options
    - X-Content-Type-Options
    - Strict-Transport-Security
    - Content-Security-Policy
    - Referrer-Policy
    - Permissions-Policy
    - Cross-Origin-Embedder-Policy
    - Cross-Origin-Resource-Policy
    - Cross-Origin-Opener-Policy

- 🟥🟩 **Color-Coded Results**
  - 🟢 Green → Header present
  - 🔴 Red → Header missing
  - Content-Security-Policy values displayed in a readable, multi-line format

- 🧹 **Clear Results**
  - Clears:
    - Analysis results
    - Request viewer
    - Response viewer
  - Prevents stale or misleading data

- 🖥 **Dedicated Burp Tab**
  - Appears as **“Sec Headers”** in Burp Suite

---

## 🖼 Screenshots

> Add screenshots in the `screenshots/` directory and reference them below.

### 🔹 Main Interface
![Main Interface](screenshots/main-ui.png)

### 🔹 Send from HTTP History
![Context Menu](screenshots/context-menu.png)

---

## 🔐 Why BuExSeHeCheck?

Security headers are frequently:
- Missing
- Misconfigured
- Inconsistently applied across endpoints

BuExSeHeCheck helps you:
- Quickly validate security hardening
- Reduce manual inspection effort
- Improve accuracy during web penetration tests

---