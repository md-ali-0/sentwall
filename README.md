# VulnScope Enterprise 2.0 — Next-Gen Security Assessment & Client Pitch Studio

> **"যেটা আগে কেউ বানায়নি"** — এটি শুধু একটি সাধারণ ভ্যালনারেবিলিটি স্ক্যানার নয়; এটি সম্পূর্ণ একটি স্বয়ংক্রিয় **Autonomous Cybersecurity Assessment & Client Conversion Platform**।

একটি মাত্র কমান্ড বা ব্রাউজার স্টুডিও ইন্টারফেসের মাধ্যমে যেকোনো ওয়েবসাইটের সম্পূর্ণ অ্যাটাক সারফেস স্ক্যান করে, দুর্বলতাগুলোর লাইভ ভেরিফিকেশন করে, সার্ভার ফিক্স তৈরি করে এবং ক্লায়েন্টকে সরাসরি দেওয়ার জন্য **এক্সিকিউটিভ পিচ ডেক, আর্থিক ক্ষতির হিসাব (Financial Exposure ROI), SARIF এবং চুক্তিপত্র (SOW)** তৈরি করে দেয়।

---

## 🔥 কী কী নতুন এবং অনন্য (100x Upgrades)

| ফিচার | বিস্তারিত বিবরণ |
|---|---|
| ⚡ **Cyberpunk Web Studio GUI** | কোনো npm/node লাগবে না! শুধু `python scan.py --serve` দিলেই লাইভ আধুনিক ডার্ক-মোড স্টুডিও চালু হয়। |
| 🕸️ **Interactive Attack Topology** | HTML5 ক্যানভাস ভিত্তিক লাইভ নোড গ্রাফ — Target ➔ DNS ➔ Ports ➔ Cloud ➔ Vulnerabilities। |
| 🛡️ **১৫টি শক্তিশালী অডিট মডিউল** | GraphQL, Swagger/OpenAPI, JWT, AWS S3/Firebase, Shannon Entropy Secret Hunter, SSRF, WAF Bypass, ইত্যাদিসহ ২৫০+ চেক। |
| 🎯 **১-ক্লিক লাইভ PoC ও Re-Test** | ব্রাউজার থেকেই সাথে সাথে ভালনারেবিলিটি রি-টেস্ট করা যায় এবং cURL / Python PoC স্ক্রিপ্ট কপি করা যায়। |
| 💰 **Financial ROI & Loss Estimator** | IBM Ponemon ও GDPR ডেটা অনুযায়ী ক্লায়েন্টের সম্ভাব্য সাইবার ব্রিচ ক্ষতির হিসাব ($) বের করে দেয়। |
| 📜 **Client Pitch & Proposal Engine** | ৩টি সার্ভিস প্যাকেজ (Tier 1 Quick Wins, Tier 2 Full Fix, Tier 3 Retainer) সহ রেডি চুক্তিপত্র। |
| 🔄 **Before vs. After Delta Re-Scan** | `python scan.py --diff scan1.json scan2.json` দিয়ে ক্লায়েন্টকে দেখানো যায় আপনার ফিক্সের পর স্কোর F থেকে A হয়েছে। |
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

### ৩.১. Cyberpunk Web Studio চালু করতে (GUI মোড)
```bash
python scan.py --serve --port 8888
```
এরপর ব্রাউজারে `http://127.0.0.1:8888` ওপেন করুন! এখানে গ্রাফ, লাইভ স্ক্যান, ফিল্টার এবং এক্সপোর্ট সেন্টার পাওয়া যাবে।

### ৩.২. CLI স্ক্যান (টার্মিনাল থেকে)
```bash
# ১. সাধারণ স্ক্যান (HTML, PDF, JSON, SARIF, CSV সহ)
python scan.py https://client-site.com --authorized

# ২. ক্লায়েন্ট পিচ সেকশন, কাস্টম নাম ও PDF সহ
python scan.py https://client-site.com --authorized --pitch \
    --client "Acme Traders Ltd" --auditor "Ali" --pdf

# ৩. ডিপ রেড-টিম স্ক্যান (Blind SQLi + Subdomain Takeover + Form Canaries)
python scan.py client-site.com --authorized --profile deep

# ৪. আধুনিক API ও ক্লাউড ফোকাসড স্ক্যান
python scan.py https://api.client.com --authorized --profile api
```

### ৩.৩. ক্লায়েন্টকে কাজ প্রমাণের জন্য (Delta Re-Scan Comparison)
কাজ করার আগে প্রথম স্ক্যানটি রাখুন (`reports/before.json`) এবং ফিক্স করার পর দ্বিতীয় স্ক্যানটি চালান (`reports/after.json`):
```bash
python scan.py --diff reports/before.json reports/after.json
```
এটি সাথে সাথে ক্লায়েন্টের জন্য রিপোর্ট দিবে:
- কতটি সমস্যা সমাধান (Resolved) হয়েছে
- রিস্ক স্কোর কতটা কমেছে (যেমন: ৮৫ থেকে নেমে ১২ হয়েছে)
- সিকিউরিটি গ্রেড F থেকে B বা A হয়েছে

### ৩.৪. CI/CD পাইপলাইন তৈরি করতে
```bash
# GitHub Actions এর জন্য
python scan.py --generate-ci github

# GitLab CI এর জন্য
python scan.py --generate-ci gitlab
```

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

প্রতিটি স্ক্যানে তৈরি হয়:
- `reports/*.html` — ইন্টারঅ্যাকটিভ ডার্ক/লাইট মোড, ফিল্টার ও PoC কপি বাটন সহ ব্রাউজারে দেখার রিপোর্ট।
- `reports/*.pdf` — প্রিন্ট-রেডি এক্সিকিউটিভ ক্লায়েন্ট পিডিএফ।
- `reports/*.sarif` — গিটহাব ও গিটল্যাব ড্যাশবোর্ডে আপলোডের জন্য অফিসিয়াল OASIS SARIF 2.1.0 ফাইল।
- `reports/*.csv` — এক্সেল বা স্প্রেডশীটে অ্যানালাইসিসের জন্য ডেটা।
- `reports/*.json` — সম্পূর্ণ র ডেটা।
- `reports/*-proposal.md` — ক্লায়েন্টের সইয়ের জন্য রেডি বাণিজ্যিক প্রস্তাব ও কাজের চুক্তিপত্র (Statement of Work)।

---

## ৬. অটোমেটেড টেস্ট রান

```bash
python -m unittest discover tests
```
*সম্পূর্ণ টেস্ট স্যুটে ১৩টি টেস্টের সবগুলো সফলভাবে পাস করে। এতে বিল্ট-ইন ভালনারেবল টেস্ট অ্যাপ (`tests/vulnerable_app.py`) এর বিরুদ্ধে লাইভ ইন্টিগ্রেশন টেস্ট অন্তর্ভুক্ত।*
