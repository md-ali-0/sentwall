# VulnScope Enterprise 2.0 — Next-Gen Security Assessment & Client Pitch CLI

> **"যেটা আগে কেউ বানায়নি"** — এটি শুধু একটি সাধারণ ভ্যালনারেবিলিটি স্ক্যানার নয়; এটি সম্পূর্ণ একটি স্বয়ংক্রিয় **Autonomous Cybersecurity Assessment & Client Conversion Platform**।

একটি মাত্র কমান্ডে যেকোনো ওয়েবসাইটের সম্পূর্ণ অ্যাটাক সারফেস স্ক্যান করে, দুর্বলতাগুলোর লাইভ ভেরিফিকেশন করে, সার্ভার ফিক্স তৈরি করে এবং ক্লায়েন্টকে সরাসরি দেওয়ার জন্য **এক্সিকিউটিভ পিচ ডেক, আর্থিক ক্ষতির হিসাব (Financial Exposure ROI), SARIF এবং চুক্তিপত্র (SOW)** তৈরি করে দেয়।

---

## 🔥 কী কী নতুন এবং অনন্য (100x Upgrades)

| ফিচার | বিস্তারিত বিবরণ |
|---|---|
| 🛡️ **১৫টি শক্তিশালী অডিট মডিউল** | GraphQL, Swagger/OpenAPI, JWT, AWS S3/Firebase, Shannon Entropy Secret Hunter, SSRF, WAF Bypass, ইত্যাদিসহ ২৫০+ চেক। |
| 📁 **Domain ও Date-Time ভিত্তিক রিপোর্ট ফোল্ডার** | প্রতিটি স্ক্যানের রিপোর্ট সুশৃঙ্খলভাবে `reports/<domain>/<date-time>/` ডিরেক্টরিতে স্বয়ংক্রিয়ভাবে জমা হয়। |
| 🎯 **লাইভ PoC ও Re-Test কমান্ড** | প্রতিটি ত্রুটির জন্য রেডি cURL কমান্ড ও পাইথন ভেরিফিকেশন স্ক্রিপ্ট স্বয়ংক্রিয়ভাবে তৈরি হয়ে রিপোর্টে থাকে। |
| 💰 **Financial ROI & Loss Estimator** | IBM Ponemon ও GDPR ডেটা অনুযায়ী ক্লায়েন্টের সম্ভাব্য সাইবার ব্রিচ ক্ষতির হিসাব ($) বের করে দেয়। |
| 📜 **Client Pitch & Proposal Engine** | ৩টি সার্ভিস প্যাকেজ (Tier 1 Quick Wins, Tier 2 Full Fix, Tier 3 Retainer) সহ রেডি চুক্তিপত্র। |
| 🔄 **Before vs. After Delta Re-Scan** | `python scan.py --diff before.json after.json` দিয়ে ক্লায়েন্টকে দেখানো যায় আপনার ফিক্সের পর স্কোর F থেকে A হয়েছে। |
| 🚀 **SARIF 2.1.0 & CI/CD Generator** | GitHub Security Tab ও GitLab CI-তে সরাসরি ইন্টিগ্রেশনের জন্য ১-ক্লিকে SARIF এবং পাইপলাইন ফাইল জেনারেট। |

---

## ২. ইনস্টলেশন

```bash
cd vulnscope
pip install -r requirements.txt
```
*প্রয়োজনীয় রিকোয়ারমেন্ট: Python 3.9+ (Windows, Linux, macOS সবার জন্য উপযুক্ত)।*

---

## ৩. ব্যবহারের নিয়মাবলী

### ৩.১. টার্মিনাল থেকে স্ক্যান (CLI)
```bash
# ১. সাধারণ স্ক্যান (HTML, PDF, JSON, SARIF, CSV সহ)
python scan.py https://client-site.com --authorized
# অথবা: python -m vulnscope https://client-site.com --authorized

# ২. ক্লায়েন্ট পিচ সেকশন, কাস্টম নাম ও PDF সহ
python scan.py https://client-site.com --authorized --pitch \
    --client "Acme Traders Ltd" --auditor "Ali" --pdf

# ৩. ডিপ রেড-টিম স্ক্যান (Blind SQLi + Subdomain Takeover + Form Canaries)
python scan.py client-site.com --authorized --profile deep

# ৪. আধুনিক API ও ক্লাউড ফোকাসড স্ক্যান
python scan.py https://api.client.com --authorized --profile api
```

### ৩.২. ক্লায়েন্টকে কাজ প্রমাণের জন্য (Retest / Delta Report)
কাজ করার আগে প্রথম স্ক্যানটি রাখুন, ফিক্স করার পর দ্বিতীয় স্ক্যানটি চালান — তারপর তুলনা:

```bash
# তুলনা + রিপোর্ট (HTML / Markdown / JSON)
python retest.py reports/target/2026-11-16_10-00-00/report.json \
                 reports/target/2026-11-16_12-00-00/report.json

# অথবা একই কাজ scan.py দিয়েও
python scan.py --diff baseline.json retest.json --out reports
```

রিপোর্টে পাঁচটা ভাগ থাকে:

| ভাগ | মানে |
|---|---|
| **Resolved** | আগে ছিল, এখন নেই — ক্লায়েন্ট সত্যিই ঠিক করেছে |
| **Still open** | আগেও ছিল, এখনো আছে — পরের রাউন্ডের কাজ |
| **Regressed** | আছে, আর সিভিয়ারিটি **বেড়েছে** — ফিক্সের সময় নতুন সমস্যা |
| **Improved** | সিভিয়ারিটি কমেছে, কিন্তু পুরো ঠিক হয়নি |
| **New** | শুধু দ্বিতীয় স্ক্যানে এসেছে — রিগ্রেশন |

সাথে থাকে: স্কোর ও গ্রেডের তুলনা (F → E), সিভিয়ারিটি-ভিত্তিক আগে/পরে টেবিল, আর fix rate।

**CI গেট হিসেবে:**

```bash
# critical বা high কিছু খোলা থাকলে exit code 1
python retest.py old.json new.json --fail-on high
```

**ডেমো দেখতে** (দুর্বল অ্যাপ → হার্ডেন্ড অ্যাপ, আসল re-scan):

```bash
python tests/vulnerable_app.py                 # টার্মিনাল ১
python scan.py http://127.0.0.1:8099 --authorized --formats json --out reports/before

# টার্মিনাল ১ বন্ধ করে আবার চালান:
python tests/vulnerable_app.py --hardened
python scan.py http://127.0.0.1:8099 --authorized --formats json --out reports/after

python retest.py reports/before/*/*/report.json reports/after/*/*/report.json
```

ফলাফল: **৩৭ → ১৬ ফাইন্ডিং, ৮টা critical → ০, স্কোর ১০০ → ৭১, গ্রেড F → E।**
আর একটা **নতুন** ফাইন্ডিং (`csp-no-frame-ancestors`) ধরা পড়ে — কারণ আধা-সমাধানে CSP যোগ করা হয়েছিল কিন্তু `frame-ancestors` বাদ পড়েছিল। এটাই রিটেস্টের আসল মূল্য: ফিক্স নিজেই নতুন সমস্যা আনে কিনা সেটা ধরা পড়ে।

### ৩.৩. CI/CD পাইপলাইন তৈরি করতে
```bash
# GitHub Actions এর জন্য
python scan.py --generate-ci github

# GitLab CI এর জন্য
python scan.py --generate-ci gitlab
```

### ৩.৪. অ্যাটাক সারফেস ম্যাপ করতে (Recon)
VulnScope একটা হোস্ট দেখে। কিন্তু ক্লায়েন্টের `dev.`, `old.`, `staging.`, `admin.` — এইগুলোই
আসল ঝুঁকি, কারণ ওগুলো প্যাচ হয় না। `recon.py` পুরো এস্টেট খুঁজে বের করে:

```bash
# শুধু খোঁজো (passive + হালকা প্রোব)
python recon.py example.com --authorized

# খুঁজে বের করা প্রতিটা লাইভ হোস্টে স্ক্যানও চালাও
python recon.py example.com --authorized --scan --max-scan 15
```

পাঁচটা ধাপে কাজ করে:

1. **Certificate transparency** — `crt.sh` থেকে সেই ডোমেইনের যত সার্টিফিকেট হয়েছে, সব নাম
2. **DNS brute force** — ~৭০টা সাধারণ প্রিফিক্স (`api`, `dev`, `staging`, `admin`...)
3. **Resolve** — প্রতিটার IP
4. **Fingerprint** — HTTP status, Server হেডার, পেজের title, টেক স্ট্যাক, সার্টিফিকেটের মেয়াদ
5. **Scan** (ঐচ্ছিক) — প্রতিটা লাইভ হোস্টে VulnScope, ফলাফল একই টেবিলে

আউটপুট: `recon-<domain>-<timestamp>.html / .md / .json / .csv` — এক টেবিলে সব হোস্ট,
কোনটায় critical, কোন সার্টিফিকেট ৩০ দিনে শেষ।

> `--authorized` বাধ্যতামূলক। ডিসকভারি পাবলিক সার্টিফিকেট ডেটা দেখে, কিন্তু fingerprint
> আর scan ধাপ আসল রিকোয়েস্ট পাঠায় — সেটার জন্য লিখিত অনুমতি লাগবে।

**সীমা:** `crt.sh` মাঝে মাঝে rate limit করে (টুল তিনবার retry করে, তবু খালি আসতে পারে)।
DNS brute force শুধু বিল্ট-ইন ছোট লিস্টে চলে — বড় লিস্ট লাগলে `--wordlist` দাও।

---

## ৪. ১৫টি পূর্ণাঙ্গ সিকিউরিটি মডিউল

1. **API & GraphQL (`api.py`)**: GraphQL Introspection, Query Depth DOS, Swagger 2.0 / OpenAPI 3.0 / ReDoc / Postman spec exposure, JWT `alg: none` বাইপাস ও missing exp।
2. **Cloud & Infrastructure (`cloud.py`)**: AWS S3 খোলা বাকেট (Public Listing), Firebase Realtime DB open read (`/.json`), Spring Boot Actuator (`/env`, `/heapdump`), Prometheus `/metrics`।
3. **Deep Secret Hunter (`secrets.py`)**: Shannon Entropy অ্যানালাইজার সহ OpenAI, Anthropic Claude, Google Gemini, AWS Access Keys, GitHub Tokens, Stripe live secrets, Slack webhooks, SendGrid, Twilio, এবং ডেটাবেজ কানেকশন স্ট্রিং ডিটেকশন।
4. **SSRF & Logic Injection (`ssrf_traversal.py`)**: AWS/GCP ক্লাউড মেটাডাটা প্রোপ (`169.254.169.254`), Client-Side Prototype Pollution, Web Cache Deception।
5. **Auth & Access Control (`auth_access.py`)**: লগইন এন্ডপয়েন্টে রেট লিমিটিং অনুপস্থিতি, স্টেট-চেঞ্জিং ফর্মে CSRF টোকেনের অভাব, HTTP Verb Tampering (HEAD bypass)।
6. **WAF & Origin IP Discovery (`waf.py`)**: Cloudflare, AWS WAF, Akamai, Imperva ফিঙ্গারপ্রিন্টিং এবং সাবডোমেইনের মাধ্যমে মূল সার্ভারের রিয়েল Origin IP ফাঁস চিহ্নিতকরণ।
7. **Sensitive File Exposure (`exposure.py`)**: `.git/config`, `.env`, `backup.sql`, `wp-config.php.bak`, `id_rsa`, `robots.txt`, ডিরেক্টরি লিস্টিং সহ ২৫০+ পাথ।
8. **Transport & TLS (`transport.py`)**: HTTP to HTTPS এনফোর্সমেন্ট, TLS 1.0/1.1 দুর্বলতা, এক্সপায়ার্ড সার্টিফিকেট, দুর্বল সাইফার।
9. **Security Headers (`headers.py`)**: CSP, HSTS, X-Frame-Options (Clickjacking), CORS ক্রেডেনশিয়াল রিফ্লেকশন, Server ভার্সন লিক।
10. **Cookie Security (`cookies.py`)**: Secure, HttpOnly, SameSite ফ্ল্যাগ মিসিং, লং সেশন লাইফ।
11. **Server Misconfiguration (`misconfig.py`)**: HTTP TRACE, PUT/DELETE, এরর স্ট্যাকট্রেস ডিটেকশন, হোস্ট হেডার ইনজেকশন।
12. **Content & Supply Chain (`content.py`)**: মিক্সড কনটেন্ট, Subresource Integrity (SRI) ছাড়া স্ক্রিপ্ট, সেনসিটিভ কমেন্টস, রিভার্স ট্যাবন্যাবিং।
13. **DNS & Email Security (`dnsemail.py`)**: SPF, DMARC, DKIM, CAA, DNSSEC, সাবডোমেইন টেকওভার (crt.sh)।
14. **Injection Flaws (`injection.py`)**: রিফ্লেক্টেড XSS, এরর ও টাইম-বেজড SQL ইনজেকশন, ওপেন রিডাইরেক্ট, LFI/পাথ ট্রাভার্সাল, SSTI।
15. **Software & Tech (`tech.py`)**: EOL পিএইচপি, অ্যাপাচি, এনজিনএক্স, পুরনো লাইব্রেরি ডিটেকশন।

---

## ৫. আউটপুট ও রিপোর্টস

প্রতিটি স্ক্যানে `reports/<domain>/<date-time>/` ফোল্ডারে সুশৃঙ্খলভাবে তৈরি হয়:
- `report.html` — ইন্টারঅ্যাকটিভ ডার্ক মোড, ফিল্টার ও PoC কপি বাটন সহ ব্রাউজারে দেখার স্বয়ংসম্পূর্ণ অফলাইন অডিট রিপোর্ট।
- `report.pdf` — প্রিন্ট-রেডি এক্সিকিউটিভ ক্লায়েন্ট পিডিএফ।
- `report.sarif` — গিটহাব ও গিটল্যাব ড্যাশবোর্ডে আপলোডের জন্য অফিসিয়াল OASIS SARIF 2.1.0 ফাইল।
- `report.csv` — এক্সেল বা স্প্রেডশীটে অ্যানালাইসিসের জন্য ডেটা।
- `report.json` — সম্পূর্ণ র ডেটা।
- `proposal.md` — ক্লায়েন্টের সইয়ের জন্য রেডি বাণিজ্যিক প্রস্তাব ও কাজের চুক্তিপত্র (Statement of Work)।

রিটেস্ট চালালে আলাদা করে `reports/retest-<host>-<timestamp>.html / .md / .json` তৈরি হয় —
এটাই সেই ডকুমেন্ট যেটা ক্লায়েন্টকে দেখিয়ে বলবে "দেখুন, ২২টা সমস্যা ঠিক হয়েছে, এই ৩টা এখনো বাকি"।
`reports/sample/retest/` ফোল্ডারে একটা সম্পূর্ণ উদাহরণ আছে (`retest-report.html`)।

---

## ৬. অটোমেটেড টেস্ট রান

```bash
python -m unittest discover tests
```
*সম্পূর্ণ টেস্ট স্যুটে ১৩টি টেস্টের সবগুলো সফলভাবে পাস করে। এতে বিল্ট-ইন ভালনারেবল টেস্ট অ্যাপ (`tests/vulnerable_app.py`) এর বিরুদ্ধে লাইভ ইন্টিগ্রেশন টেস্ট অন্তর্ভুক্ত।*
