# Domain Mirror - Burp Suite Extension

A Burp Suite extension for comparing HTTP responses across multiple domains with automatic authentication handling. Perfect for testing multi-tenant applications, staging vs. production comparisons, or any scenario where you need to verify response consistency across environments.

## Features

### Core Functionality
- **Multi-Domain Mirroring**: Automatically replay requests from a primary domain to one or more mirror domains
- **Response Comparison**: Compare responses using MD5 hashing with detailed diff viewing
- **Session Management**: Automatic capture and transfer of authentication (cookies, Bearer tokens, custom headers)
- **Real-Time Monitoring**: Live results as you browse through the proxy

### Authentication Modes
| Mode | Description |
|------|-------------|
| **Auto Detect** | Automatically detects and transfers cookies and Bearer tokens |
| **Cookies Only** | Only transfer cookies between domains |
| **Bearer Only** | Only transfer Bearer/JWT tokens |
| **Both** | Transfer both cookies and Bearer tokens |
| **None** | Don't transfer any authentication |
| **Custom Header** | Use a custom header (e.g., `X-API-Key`) |

### Tool Interception
Configure which Burp tools trigger mirroring:
- **Proxy** (enabled by default)
- **Repeater**
- **Scanner**
- **Intruder**
- **Extensions** (safe from infinite loops)

### Diff Viewing
Four comparison views for analyzing mismatches:
1. **Summary**: Quick overview with status codes, sizes, and hashes
2. **Diff View**: Unified diff with color highlighting (red=removed, green=added)
3. **Full Response**: Complete response body for any domain
4. **Side-by-Side**: Visual comparison with synchronized scrolling

### Session Persistence
- **Save Session**: Export all results to JSON for later analysis
- **Load Session**: Import previous session results (merge or replace)
- Results survive between Burp restarts when saved

## Installation

### Prerequisites
- Burp Suite Professional or Community Edition
- Jython standalone JAR (2.7.x recommended)

### Steps
1. Download Jython standalone from [jython.org](https://www.jython.org/download)
2. In Burp Suite, go to **Extensions** → **Extension Settings**
3. Under "Python Environment", set the path to your Jython JAR
4. Go to **Extensions** → **Add**
5. Set Extension type to **Python**
6. Select `DomainMirrorV5.py`
7. Click **Next** to load the extension

## Quick Start

### Basic Setup
1. Go to the **Domain Mirror** tab in Burp
2. Click **Add Domain** and enter your primary domain (e.g., `app.example.com`)
   - Check "Set as Primary" 
   - Select auth mode (Auto Detect recommended)
3. Click **Add Domain** again for your mirror domain (e.g., `staging.example.com`)
   - Leave "Set as Primary" unchecked
   - Configure auth mode as needed

### Capturing Sessions
1. Browse to your primary domain in the browser (with proxy enabled)
2. Log in to capture authentication tokens
3. The extension will automatically capture cookies and tokens
4. Check the **Domains** tab to verify session status

### Starting Comparison
1. Check **Enable Mirroring** in the control panel
2. Browse your primary domain normally
3. Watch the **Results** tab for comparison results
4. Click any result to see detailed comparison

## User Interface

### Tabs Overview

#### Domains Tab
Manage your domain configurations:
- Add/Edit/Remove domains
- Set primary domain
- View captured session info
- Manual session refresh

#### Results Tab
View and analyze comparison results:
- Filter: All / Mismatches Only / Matches Only
- Sort by: #, Method, Path, Match status, Time
- Export: CSV, Diff Report, Save/Load Session
- Results count with mismatch statistics

#### Settings Tab
Configure extension behavior:
- Tool interception settings
- Debug logging toggle
- Auto-refresh mirrors option

#### Logs Tab
Monitor extension activity:
- Real-time logging
- Debug mode toggle (off by default)
- Clear logs button

## Configuration Options

### Settings Panel - Tool Interception
| Setting | Description | Default |
|---------|-------------|---------|
| Mirror from Proxy | Mirror requests from Proxy tool | ✓ Enabled |
| Mirror from Repeater | Mirror requests from Repeater | Disabled |
| Mirror from Scanner | Mirror requests from Scanner | Disabled |
| Mirror from Intruder | Mirror requests from Intruder | Disabled |
| Mirror from Extensions | Mirror requests from other extensions | Disabled |
| Auto-refresh Mirrors | Update mirror sessions when primary refreshes | ✓ Enabled |

### Settings Panel - Resource Limits
| Setting | Description | Default | Range |
|---------|-------------|---------|-------|
| Max stored results | Maximum results to keep in memory | 1,000 | 10-100,000 |
| Max concurrent mirrors | Simultaneous mirror threads | 10 | 1-50 |
| Request timeout | Seconds to wait per request | 15 | 1-120 |
| Max diff lines | Lines shown in diff view | 500 | 50-10,000 |

### Results Panel
| Setting | Description | Default |
|---------|-------------|---------|
| Filter | Show All/Mismatches Only/Matches Only | All |
| Max body display | Truncate body display (500/2000/5000/Full) | Full |
| Sort by | Result ordering | # (Newest First) |

## Understanding Results

### Match Status
- **YES (Green)**: All domains returned identical response bodies
- **NO (Red)**: Response differences detected between domains

### Response Comparison
The extension compares:
- Response body content (MD5 hash)
- Status codes (shown in summary)
- Response sizes (shown in summary)

### Diff View Colors
- 🟥 **Red background**: Lines present in primary but not in mirror
- 🟩 **Green background**: Lines present in mirror but not in primary  
- 🟨 **Yellow background**: Modified lines
- 🔵 **Blue headers**: Section markers (@@ lines)

## Troubleshooting

### No Responses Being Mirrored
1. Verify "Enable Mirroring" is checked
2. Check that primary domain is correctly set
3. Verify at least one tool is enabled in Settings
4. Check the Logs tab for errors

### Authentication Not Working
1. Browse to the primary domain and log in first
2. Check the Domains tab - session info should show captured tokens
3. Try clicking "Refresh All Sessions"
4. Verify auth mode is appropriate for your application

### Getting 302 Redirects on Mirrors
This means the mirror domain isn't recognizing the session:
1. Enable **Debug Logging** in the Logs tab
2. Look for messages like:
   - `WARNING: domain.com has no captured session!`
   - `WARNING: No mirror cookies - using original (primary) cookies!`
3. **Fix**: Browse directly to the mirror domain and log in
4. Check the Domains tab shows session info for that domain
5. The extension will warn you in the logs about 302s: `302 (REDIRECT - session issue?)`

### Timeout Errors
1. Verify mirror domain is accessible from your machine
2. Check firewall/proxy settings
3. Try the "Test Connectivity" button
4. Increase timeout if needed (default: 15 seconds)

### High Memory Usage
The extension includes configurable safeguards (Settings tab → Resource Limits):
- Increase/decrease max stored results as needed
- Adjust max concurrent mirrors for your system
- Large responses may still consume memory

Consider:
- Clearing results periodically
- Saving sessions and clearing
- Reducing max stored results for long sessions
- Disabling Scanner/Intruder mirroring for high-volume scans

### UI Freezing When Clicking Results
Large responses can cause temporary freezes. The extension mitigates this by:
- Processing diffs in background threads
- Showing "Loading..." while processing
- Limiting diff body size to 100KB
- Limiting side-by-side to 50KB

If you still experience freezes:
- Reduce "Max diff lines" in Settings
- Use the Summary tab for quick overviews
- Large responses (>100KB) will show truncation warnings

### Extension Causing Issues
1. Disable mirroring first (uncheck "Enable Mirroring")
2. Check Logs tab for errors (enable Debug if needed)
3. Try removing and re-adding the extension
4. Check Burp's Extender → Errors tab

## Safety Features

### Infinite Loop Prevention
- All mirrored requests include `X-DomainMirror-Internal: true` header
- Extension detects and skips its own requests
- Safe to enable "Extensions" tool interception

### Resource Limits (Configurable)
All limits can be adjusted in the Settings tab:

| Setting | Default | Range | Description |
|---------|---------|-------|-------------|
| Max stored results | 1,000 | 10-100,000 | Results auto-cleanup when exceeded |
| Max concurrent mirrors | 10 | 1-50 | Requests skipped when exceeded |
| Request timeout | 15s | 1-120s | Per mirror request |
| Max diff lines | 500 | 50-10,000 | Prevents UI freeze on large diffs |

### Thread Safety
- All shared data protected by locks
- UI updates via SwingUtilities.invokeLater()
- All threads marked as daemon (won't prevent Burp exit)
- Safe concurrent access to domains and results

### Performance Optimizations
The extension uses several techniques to prevent UI freezes:
- **Background Processing**: Diff calculations run in background threads
- **Loading Indicators**: "Loading..." shown immediately while processing
- **Size Limits**: 
  - Diff calculation limited to 100KB per body
  - Side-by-side comparison limited to 50KB per body
  - Larger responses are truncated with a warning
- **Lazy Loading**: Heavy tabs only process when selected
- **Configurable Limits**: Adjust max diff lines in Settings

## Export Formats

### CSV Export
Basic export with columns:
- #, Method, Path, Match, Domains, Timestamp

### Diff Report
Detailed text report including:
- All mismatched requests
- Full unified diffs
- Complete response bodies

### Session JSON
Complete session data:
- All results with full response bodies
- Timestamps and metadata
- Can be re-imported later

## API / Programmatic Usage

The extension registers as both:
- `IProxyListener` - for Proxy traffic
- `IHttpListener` - for other tools (Repeater, Scanner, etc.)

Key methods:
```python
# Enable/disable mirroring programmatically
extender.mirror_enabled = True

# Access results
for i in range(extender.results.size()):
    result = extender.results.get(i)
    print(result["path"], result["match"])
```

## Known Limitations

1. **Response body only**: Currently compares body content, not headers
2. **No WebSocket support**: HTTP/HTTPS only
3. **Single primary**: Only one domain can be primary at a time
4. **Memory usage**: Large responses stored in memory
5. **No regex filtering**: Cannot filter which paths to mirror

## Version History

### v5.0 (Current)
- Full response diff viewing with syntax highlighting
- Side-by-side comparison with synchronized scrolling
- Configurable tool interception (Proxy, Repeater, Scanner, etc.)
- Session save/load for persistence across restarts
- Sortable and filterable results table
- Debug logging toggle (off by default)
- Resource limits and safety features
- Infinite loop prevention for Extensions tool

### v4.0
- Multi-domain support
- Authentication mode configuration
- Basic response comparison

## License

This extension is provided as-is for security testing purposes. Use responsibly and only on systems you have permission to test.

## Support

For issues or feature requests, check the Logs tab with Debug enabled and include:
1. Burp Suite version
2. Jython version
3. Error messages from Logs tab
4. Steps to reproduce

---

**Happy Testing!** 🔍
