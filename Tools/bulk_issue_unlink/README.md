# Cortex XDR Bulk Issue Unlink Tool

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Cortex XDR](https://img.shields.io/badge/Cortex-XDR-red.svg)](https://www.paloaltonetworks.com/cortex/xdr)

Automate the bulk unlinking of issues from Cortex XDR cases using multi-threaded API calls with automatic retry logic.

## 🚀 Features

- **Multi-threaded Processing**: Concurrent API calls with configurable worker threads (default: 30)
- **Automatic Retries**: Built-in retry mechanism with exponential backoff
- **Multi-Round Recovery**: Failed issues are automatically re-attempted across 5 rounds
- **Thread-safe Execution**: Prevents race conditions with proper locking mechanisms
- **Real-time Logging**: Per-issue execution timing and detailed progress tracking
- **Graceful Interruption**: Handles Ctrl+C interrupts gracefully

## 📋 Prerequisites

- Python 3.8 or higher
- `requests` library

```bash
pip install requests
```

## 🔧 Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/cortex-xdr-bulk-unlink.git
cd cortex-xdr-bulk-unlink
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## 🔑 Configuration

### Step 1: Set Your Region and Tenant

Update these variables at the top of the script:

```python
REGION = "jp"              # Your region: us, eu, jp, au, etc.
TenantName = "XSIAM"       # Your tenant name (from your Cortex XDR URL)
CASE_ID = 109203           # The case ID you're working with
```

The script will automatically construct:
- `BASE_URL = "https://XSIAM.xdr.jp.paloaltonetworks.com"`
- `REFERER = "https://XSIAM.xdr.jp.paloaltonetworks.com/case/alerts_and_insights?caseId=109203"`

### Step 2: Extract Session Credentials

The script requires the following credentials from your active Cortex XDR session:

1. **Open Cortex XDR** in your browser: `https://{TenantName}.xdr.{REGION}.paloaltonetworks.com`
2. **Open DevTools** (F12 or Cmd+Option+I on Mac)
3. **Go to Network tab** and perform any action (e.g., navigate to a case)
4. **Find any API request** in the Network tab
5. **Right-click → Copy → Copy as cURL** or view the Headers tab
6. **Extract the following from Request Headers**:
   - `Cookie` - the entire cookie header value (contains session tokens)
   - `X-CSRF-TOKEN` - typically a 32-character hexadecimal string
   - `X-XSRF-TOKEN` - JWT token starting with "Bearer eyJ..."
   - `X-XDR-REQUEST-TOKEN` - UUID format like "12345678-1234-1234-1234-567812345678"

### Step 3: Update the Script

Edit `bulk-unlink-issues.py` and replace the mock values:

```python
CSRF_TOKEN = "b0a82900ba3f4643263bb65432dcce83"  # From DevTools
XSRF_TOKEN = "Bearer eyJhbGci..."                 # Full JWT from DevTools
XDR_REQUEST_TOKEN = "2136235g-a9v4-41b6..."      # UUID from DevTools
COOKIE = "app-proxy-hydra-prod-jp=eyJ..."        # Full cookie string from DevTools
```

### Step 4: Add Issues to Unlink

In the `UNLINK_DATA` list, add your issue IDs. The script uses the `CASE_ID` variable automatically:

```python
UNLINK_DATA = [
    (734414, CASE_ID),
    (734415, CASE_ID),
    (734416, CASE_ID),
    (734417, CASE_ID),
    # ... more issues
]
```

## 📖 Usage

### Basic Usage

```bash
python3 bulk-unlink-issues.py
```

### Expected Output

```
🚀 Starting bulk unlink operation...
⏰ Started at: 2026-02-02 12:48:32

📊 Total operations: 7
🧵 Concurrent workers: 30
🔁 Max rounds for failed issues: 5

🔁 Round 1/5 - Pending issues: 7
[1/7] ✅ Issue 734414 - Success (523ms)
[2/7] ✅ Issue 734415 - Success (481ms)
[3/7] ⚠️  Issue 734416 - Retry 1/3 (HTTP 408)
[3/7] ✅ Issue 734416 - Success (1205ms)
[4/7] ✅ Issue 734417 - Success (456ms)
[5/7] ✅ Issue 734418 - Success (512ms)
[6/7] ✅ Issue 734419 - Success (489ms)
[7/7] ✅ Issue 734420 - Success (498ms)

============================================================
📈 SUMMARY
============================================================
⏰ Started at:  2026-02-02 12:48:32
⏰ Finished at: 2026-02-02 12:48:38
⏱️  Total time:  6 seconds

✅ Successful: 7
❌ Failed: 0

✨ Done!
```

## ⚙️ Configuration Options

### Concurrency

Modify `MAX_CONCURRENT` to control thread pool size:

```python
MAX_CONCURRENT = 30  # Increase for faster processing (use caution)
```

### Internal Retries

Modify `MAX_RETRIES` for retry attempts per issue:

```python
MAX_RETRIES = 3  # Number of retries per issue before moving to next round
```

### Multi-Round Retries

Modify `MAX_ROUNDS` to control how many times failed issues are retried:

```python
MAX_ROUNDS = 5  # Total rounds of re-attempts for failed issues
```

## 🔄 Retry Logic

The script implements a two-level retry mechanism:

1. **Internal Retries** (`MAX_RETRIES = 3`):
   - Each issue gets 3 attempts within a single round
   - 500ms delay between attempts

2. **Round-based Retries** (`MAX_ROUNDS = 5`):
   - After each round, failed issues are collected and re-run
   - Only issues that fail all internal retries are carried to the next round
   - Maximum 5 total rounds

## 📊 Output Interpretation

| Symbol | Meaning |
|--------|---------|
| ✅ | Issue successfully unlinked |
| ⚠️ | Retrying issue (internal retry) |
| ❌ | Issue permanently failed (after all retries) |
| 🔁 | Starting a new round for failed issues |

## 🚨 Troubleshooting

### "401 Unauthorized" or "403 Forbidden"
- **Issue**: Session tokens have expired or are invalid
- **Solution**: Re-extract all tokens from DevTools Network tab (session typically expires after 15-60 minutes)

### "408 Request Timeout"
- **Issue**: Server is busy or rate-limited
- **Solution**: Reduce `MAX_CONCURRENT` or increase sleep times
```python
MAX_CONCURRENT = 10  # Lower thread count
```

### High Failure Rate
- **Issue**: Network issues or session expired
- **Solution**: 
  1. Check internet connectivity
  2. Re-authenticate and get fresh tokens
  3. Run script again (will retry all failures)

## 📝 Example Workflow

```bash
# 1. Prepare your issues list in bulk-unlink-issues.py
# 2. Extract credentials from browser DevTools
# 3. Update configuration in the script
# 4. Run the script
python3 bulk-unlink-issues.py

# 5. Check results
# - Successfully unlinked issues are logged
# - Failed issues are listed in summary
# - Script automatically retries failed issues 5 times

# 6. (Optional) For any remaining failures, update UNLINK_DATA and re-run
```

## 🔒 Security Notes

- **Never commit credentials** to version control
- Use environment variables for sensitive data:
```bash
export CSRF_TOKEN="your-token"
export XSRF_TOKEN="your-token"
```

Then in the script:
```python
import os
CSRF_TOKEN = os.getenv("CSRF_TOKEN", "default-value")
```

## 📦 Requirements

See `requirements.txt`:
```
requests>=2.28.0
```

## 📄 License

MIT License - see LICENSE file for details

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Commit changes (`git commit -am 'Add improvement'`)
4. Push to branch (`git push origin feature/improvement`)
5. Open a Pull Request

## 🐛 Bug Reports

Please open an issue with:
- Error message (full stack trace)
- Steps to reproduce
- Expected vs. actual behavior
- Python version and OS

## 📞 Support

For Cortex XDR API questions, see [Palo Alto Networks Documentation](https://docs.paloaltonetworks.com/cortex/cortex-xdr.html)

## ⚡ Performance Tips

- **Increase threads** for faster processing (be mindful of API rate limits)
- **Batch by case ID** if unlinking from multiple cases
- **Run during off-peak hours** to avoid hitting rate limits
- **Monitor API responses** - if seeing 408/429 errors, reduce `MAX_CONCURRENT`

## 🗺️ Roadmap

- [ ] Environment variable configuration
- [ ] CSV/JSON input file support
- [ ] Progress bar integration
- [ ] Database persistence of results
- [ ] Automated credential refresh via browser extension
- [ ] Slack/Email notifications on completion

---

**Made with ❤️ for Cortex XDR automation**
