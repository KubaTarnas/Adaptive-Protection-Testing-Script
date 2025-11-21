# Adaptive Protection Testing Script

A lightweight HTTP load generator designed for testing Google Cloud Armor Adaptive Protection
and WAF signature tuning.

It simulates realistic client behavior using configurable:
- Requests per second (RPS)
- Duration
- Concurrent connections
- Multi-path traffic distribution
- Custom User-Agent headers
- JA3/TLS impersonation using curl_cffi

Supports two execution modes:
- **thread mode** – using `requests` or `curl_cffi` (recommended for WAF testing)
- **async mode** – using `httpx` with optional HTTP/2 support

Useful for:
- Testing Cloud Armor behavior in **enforced vs preview** mode
- Triggering specific attack signatures for evaluation
- Validating latency impact and error rates under load

---

## 🔧 Usage Examples

### Thread mode + JA3 impersonation (WAF evaluation)
```sh
python3 adaptive_protection_test.py \
  --url https://abc.test.com \
  --path /login \
  --rps 55 \
  --connections 120 \
  --duration 520 \
  --user-agent "Kuba-Test-AP-script-login-99" \
  --mode thread \
  --timeout 10
