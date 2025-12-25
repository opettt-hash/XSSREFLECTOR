# XSS Reflector (XSS Pro Max)

**XSS Reflector** adalah tools otomatis untuk **mendeteksi kerentanan Cross-Site Scripting (XSS)** dengan pendekatan **hybrid**:
- Reflected XSS
- Static DOM-based XSS
- Endpoint discovery dari JavaScript
- Analisis Content Security Policy (CSP)
- Deteksi indikasi WAF

Tool ini dirancang untuk **bug bounty, pentesting, dan security research**.

---

## Fitur Utama

 Ekstraksi endpoint dari
- HTML forms
- JavaScript (fetch, axios, jQuery, WebSocket, dll)

 Payload XSS pintar
- Raw payload
- URL encoded
- Base64 encoded
- Payload mutation (WAF bypass dll)

Deteksi
- Reflected XSS
- Context (HTML / Attribute / JS)
- Static DOM XSS (source → sink)
- CSP lemah (`unsafe-inline`, `unsafe-eval`)
- WAF (403 / 406)

Severity Scoring
- LOW
- MEDIUM
- HIGH
- CRITICAL

Output laporan JSON Lengkap ✓

---

## Instalasi

Pastikan Python **3.8+** sudah terinstall!

```bash
pip install requests beautifulsoup4 colorama tabulate esprima
