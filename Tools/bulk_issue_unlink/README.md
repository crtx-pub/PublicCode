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

### Getting Session Credentials

The script requires the following credentials from your Cortex XDR session:

1. **Open Cortex XDR** in your browser
2. **Open DevTools** (F12 or Cmd+Option+I)
3. **Go to Network tab** and perform an unlink action
4. **Find the `unlink_issue` request**
5. **Copy the request headers**:
   - `Cookie` (session cookies)
   - `X-CSRF-TOKEN`
   - `X-XSRF-TOKEN`
   - `X-XDR-REQUEST-TOKEN`

### Updating the Script

Edit `bulk-unlink-issues.py` and update the configuration section:

```python
# =============================================================================
# CONFIGURATION - Update these values from your browser session
# =============================================================================
BASE_URL = "https://runtime.xdr.<region>.paloaltonetworks.com"
CSRF_TOKEN = "your-csrf-token-here"
XSRF_TOKEN = "Bearer your-xsrf-token-here"
XDR_REQUEST_TOKEN = "your-request-token-here"
REFERER = "https://runtime.xdr.<region>.paloaltonetworks.com/case/alerts_and_insights?caseId=YOUR_CASE_ID"

COOKIE = "your-full-cookie-string-here"
```

### Adding Issues to Unlink

In the `UNLINK_DATA` list, add tuples of `(issue_id, case_id)`:

```python
UNLINK_DATA = [
    (734717, 109203),
    (734782, 109203),
    (734789, 109203),
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

📊 Total operations: 100
🧵 Concurrent workers: 30
🔁 Max rounds for failed issues: 5

🔁 Round 1/5 - Pending issues: 100
[1/100] ✅ Issue 734717 - Success (523ms)
[2/100] ✅ Issue 734782 - Success (481ms)
[3/100] ⚠️  Issue 734789 - Retry 1/3 (HTTP 408)
[3/100] ✅ Issue 734789 - Success (1205ms)
...

============================================================
📈 SUMMARY
============================================================
⏰ Started at:  2026-02-02 12:48:32
⏰ Finished at: 2026-02-02 12:52:45
⏱️  Total time:  253 seconds

✅ Successful: 100
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
- **Issue**: Session tokens have expired
- **Solution**: Re-extract tokens from DevTools (they expire after 15-60 minutes)

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
