# VulnScope — Website Vulnerability Scanner + Client Report Generator

একটা কমান্ড দিলেই যেকোনো ওয়েবসাইট স্ক্যান করে সব ধরনের security দুর্বলতা খুঁজে বের করে,
আর একটা **প্রফেশনাল রিপোর্ট** (HTML + PDF) বানিয়ে দেয় — যেটা তুমি সরাসরি ক্লায়েন্টকে
দিতে পারবে: "আপনাদের সাইটে এই এই সমস্যা আছে, আমি ঠিক করে দিতে পারব।"

---

## ১. এটা কী করে

| ধাপ | কী হয় |
|---|---|
| Crawl | সাইটের পেজ, লিংক, ফর্ম, প্যারামিটার খুঁজে বের করে |
| Scan | ৯টা মডিউলে ৬০+ ধরনের চেক চালায় (নিচে লিস্ট) |
| Score | ০–১০০ risk score + A–F গ্রেড দেয় |
| Report | কভার পেজ, executive summary, প্রতিটা finding-এর evidence + fix, roadmap, proposal সহ রিপোর্ট |

**কোনো ভারী টুল ইনস্টল করতে হয় না** — শুধু Python আর `requests`। Nmap, Burp, Nessus লাগবে না।

---

## ২. ইনস্টল

```bash
cd vulnscope
pip install -r requirements.txt
```

Python 3.9+ লাগবে। (Windows-এ Chrome/Edge থাকলে PDF-ও অটো বানাবে।)

---

## ৩. ব্যবহার

```bash
# সাধারণ স্ক্যান
python scan.py https://client-site.com --authorized

# ক্লায়েন্টের নাম দিয়ে, proposal section সহ, PDF সহ
python scan.py https://client-site.com --authorized --pitch \
    --client "Acme Traders Ltd" --auditor "তোমার নাম" --pdf

# গভীর স্ক্যান (blind SQLi + subdomain takeover সহ)
python scan.py client-site.com --authorized --deep --subdomains

# লগইন করা অবস্থায় স্ক্যান (cookie দিয়ে)
python scan.py https://app.client.com --authorized --cookie "session=abc123"
```

`--authorized` না দিলে টুলটা নিজেই জিজ্ঞেস করবে — অনুমতি আছে কিনা।

### সব অপশন

| অপশন | কাজ |
|---|---|
| `--authorized` / `-y` | অনুমতি Confirmation স্কিপ করে (স্ক্রিপ্টে চালানোর জন্য) |
| `--pitch` | রিপোর্টে "Recommended engagement" + pricing টেবিল যোগ করে |
| `--client "নাম"` | কভার পেজে ক্লায়েন্টের নাম |
| `--auditor "নাম"` | কভার পেজে তোমার নাম/কোম্পানি |
| `--pdf` | PDF ভার্সনও বানায় |
| `--deep` | ধীর চেক (time-based blind SQLi) চালু |
| `--subdomains` | crt.sh থেকে subdomain বের করে takeover চেক করে |
| `--test-forms` | ফর্মে নিরাপদ canary পাঠিয়ে XSS চেক করে |
| `--max-pages N` | সর্বোচ্চ কত পেজ crawl করবে (ডিফল্ট ২৫) |
| `--delay 0.5` | রিকোয়েস্টের মাঝে বিরতি (ধীর সার্ভারের জন্য) |
| `--cookie "..."` | লগইন সেশন |
| `--header "K: V"` | কাস্টম হেডার (API key ইত্যাদি) |
| `--proxy http://127.0.0.1:8080` | Burp/ZAP দিয়ে ট্রাফিক দেখতে |

---

## ৪. কী কী দুর্বলতা খোঁজে

**Encryption / TLS**
- HTTP-তে সাইট খোলা আছে কিন্তু HTTPS-এ redirect নেই
- সার্টিফিকেট expired / self-signed / untrusted / ৩০ দিনে expire
- TLS 1.0 / 1.1 চালু, weak cipher (RC4/3DES), ছোট RSA key, SHA-1 signature

**Security Headers**
- CSP নেই বা `unsafe-inline` সহ দুর্বল, HSTS নেই/ভুল, X-Frame-Options নেই (clickjacking),
  X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP
- Server / X-Powered-By দিয়ে version ফাঁস

**Session / Cookies**
- `Secure`, `HttpOnly`, `SameSite` ফ্ল্যাগ নেই
- SameSite=None কিন্তু Secure নেই, ১ বছরের বেশি লাইফ, পুরো ডোমেইনে ছড়ানো cookie

**Server Misconfiguration**
- CORS যেকোনো origin reflect করে **credentials সহ** (এটা সবচেয়ে ভয়ংকরগুলোর একটা)
- HTTP TRACE চালু, PUT/DELETE advertised
- Error page-এ stack trace / SQL error / framework path ফাঁস
- Host header injection

**Exposed Files (১০০+ path)**
- `.git/config`, `.env`, `backup.sql`, `www.zip`, `id_rsa`, `.aws/credentials`
- `phpinfo.php`, `server-status`, Spring `actuator/env`, Laravel `telescope`, `_profiler`
- Directory listing, admin panel, phpMyAdmin, XML-RPC, robots.txt-এর সংকেত

**Injection (non-destructive)**
- Reflected XSS (canary tag দিয়ে, script চালায় না)
- SQL injection (error-based signature মিলিয়ে; `--deep` এ time-based blind)
- Open redirect, Path traversal / LFI, SSTI, CRLF header injection

**Content / Supply chain**
- JS ফাইলে AWS key, Stripe live key, GitHub token, hardcoded password
- Mixed content, SRI ছাড়া third-party script, sensitive HTML comment, tabnabbing

**DNS / Email**
- SPF নেই / `+all` / `?all` / lookup limit, DMARC নেই বা `p=none`, DKIM নেই, CAA নেই
- DNSSEC নেই, subdomain takeover (CNAME dangling)

**Outdated Software**
- EOL PHP / nginx / Apache / IIS / OpenSSL
- Apache 2.4.49–2.4.50 (CVE-2021-41773), পুরনো jQuery, Bootstrap, WordPress

---

## ৫. রিপোর্ট

`reports/` ফোল্ডারে তিনটা ফাইল তৈরি হয়:

```
reports/vulnscope-client-site-com-20261116-101500.html   ← ব্রাউজারে খোলো
reports/vulnscope-client-site-com-20261116-101500.pdf    ← ক্লায়েন্টকে পাঠাও
reports/vulnscope-client-site-com-20261116-101500.json   ← ডেটা, নিজের ট্র্যাকিংয়ের জন্য
```

রিপোর্টে থাকে:
1. **Cover** — টার্গেট, তারিখ, রিপোর্ট আইডি, গ্রেড (A–F)
2. **Executive summary** — মালিক/ম্যানেজার পড়বে, ব্যবসার ভাষায়
3. **Risk overview** — score gauge + severity distribution
4. **Findings summary** — এক টেবিলে সব
5. **Detailed findings** — প্রতিটার জন্য: কী পাওয়া গেছে, ব্যবসায় কী ক্ষতি, **evidence**, **ঠিক করার ধাপ (কোড সহ)**, CVSS, CWE, OWASP
6. **Remediation roadmap** — Phase 1 (এই সপ্তাহে) / Phase 2 / Phase 3
7. **Compliance mapping** — OWASP Top 10 টেবিল
8. **Recommended engagement** (`--pitch` দিলে) — Essential / Complete / Retainer প্যাকেজ
9. **Appendix** — headers, TLS, DNS records, crawl করা URL
10. **Methodology & limitations** — কী টেস্ট করা হয়েছে, কী হয়নি

---

## ৬. ক্লায়েন্ট পাওয়ার বাস্তব ওয়ার্কফ্লো

1. **প্রথমে ফ্রি মিনি-স্ক্যান** — শুধু `--max-pages 5` দিয়ে চালাও। রিপোর্টের প্রথম ২ পেজ (summary + top 3 issue) স্ক্রিনশট নিয়ে ক্লায়েন্টকে পাঠাও।
2. **"আপনাদের সাইটে ৮টা critical সমস্যা আছে"** — রিপোর্টের গ্রেড আর top issues দেখাও। ভয় দেখানো না, সমাধান দেখাও।
3. **`--pitch` দিয়ে পূর্ণ রিপোর্ট** — pricing টেবিলে নিজের রেট বসাও।
4. **কাজ নেওয়ার পর** — ফিক্স করে আবার স্ক্যান করাও। "Before: F (100/100) → After: A (8/100)" — এই before/after টাই তোমার সেরা মার্কেটিং।

> টিপ: প্রতিটা ক্লায়েন্টের রিপোর্ট আলাদা ফোল্ডারে রাখো (`--out reports/acme`), আর JSON ফাইলটা রেখে দাও — পরে re-scan করে তুলনা করতে পারবে।

---

## ৭. আইনি সতর্কতা (খুব গুরুত্বপূর্ণ)

- **যে সাইট তোমার না, সেটা স্ক্যান করা আইনত অপরাধ।** বাংলাদেশে ICT Act 2006 (সংশোধিত 2013) ধারা ৫৭/৬৬, আর প্রায় সব দেশে equivalent law আছে।
- স্ক্যান করার আগে **লিখিত অনুমতি** নাও — ইমেইল/WhatsApp মেসেজ হলেও চলবে, যেখানে scope আর তারিখ লেখা থাকে। সেটা সংরক্ষণ করো।
- শুধু **তোমার নিজের সাইট**, অথবা **যে ক্লায়েন্ট লিখে অনুমতি দিয়েছে**, তার সাইটে চালাও।
- শেয়ারড হোস্টিং-এ স্ক্যান করলে একই সার্ভারের অন্য সাইটেও লোড পড়তে পারে — `--delay 0.5` দিয়ে ধীরে চালাও।
- এই টুল **non-destructive** — কোনো ডেটা লেখে/মোছে না, brute force করে না, DoS করে না। তবু দায়িত্ব তোমার।

---

## ৮. সীমাবদ্ধতা (ক্লায়েন্টকে যা বলবে)

এই টুল অটোমেটেড বেসলাইন স্ক্যান — এটা দিয়ে **সব** দুর্বলতা পাওয়া যাবে না। এটা যা করে না:

- লগইন করা ইউজারের ভেতরের (authenticated) দুর্বলতা
- Business logic flaw (দাম বদলানো, coupon abuse, race condition)
- Source code review, server/network level pentest
- Mobile app, API client testing

তাই রিপোর্টে "Automated baseline assessment" লিখে দেয়, আর methodology সেকশনে স্পষ্ট করে বলে দেয় কী টেস্ট হয়নি। এতে ক্লায়েন্টের কাছে তোমার ক্রেডিবিলিটি বাড়ে, কমে না।

---

## ৯. প্রজেক্ট স্ট্রাকচার

```
vulnscope/
├── scan.py                  # CLI entry point
├── requirements.txt
├── vulnscope/
│   ├── models.py            # Finding / ScanResult / scoring
│   ├── net.py               # HTTP client, DNS resolver, TLS inspection
│   ├── crawl.py             # crawler + param/form discovery
│   ├── context.py           # shared scan context
│   ├── report.py            # HTML / PDF / JSON / Markdown renderer
│   └── checks/
│       ├── transport.py     # HTTPS, TLS, certificate
│       ├── headers.py       # CSP, HSTS, framing, banners
│       ├── cookies.py       # cookie flags
│       ├── misconfig.py     # CORS, methods, errors, host header
│       ├── tech.py          # fingerprint + outdated versions/CVE
│       ├── content.py       # secrets, mixed content, SRI
│       ├── exposure.py      # sensitive files, admin panels, listing
│       ├── dnsemail.py      # SPF, DMARC, DKIM, CAA, subdomains
│       └── injection.py     # XSS, SQLi, redirect, traversal, SSTI, CRLF
├── tests/
│   └── vulnerable_app.py    # নিজে টেস্ট করার জন্য ইচ্ছাকৃত দুর্বল লোকাল অ্যাপ
└── reports/
```

---

## ১০. নিজে টেস্ট করা

```bash
# টার্মিনাল ১
python tests/vulnerable_app.py

# টার্মিনাল ২
python scan.py http://127.0.0.1:8099 --authorized --max-pages 12 --depth 2 --pdf
```

রিপোর্টে ~৮টা critical (CVE, CORS, .env, .git, SQLi, SSTI, LFI) আর ~৬টা high পাওয়া উচিত।
নাহলে কিছু একটা ভাঙছে — ইস্যু দেখো।

---

## ১১. পরে কী যোগ করা যায়

- PDF-এ তোমার লোগো / ব্র্যান্ড কালার (report.py-র CSS-এ বদলাও)
- Slack/Telegram-এ scan result পাঠানো
- একাধিক সাইট একসাথে স্ক্যান (একটা `targets.txt` লুপ)
- আগের JSON-এর সাথে তুলনা করে "নতুন কী যোগ হলো" ডিফ রিপোর্ট
- Screenshot-সহ PoC (Selenium দিয়ে)

---

**মনে রাখো:** এই টুল বিক্রি হয় "রিপোর্ট" দিয়ে না, **"ফিক্স করে দেওয়া"** দিয়ে।
স্ক্যানার শুধু দরজা খুলে দেয় — আসল ব্যবসা হলো ওই সমস্যাগুলো ঠিক করে দেওয়া।
