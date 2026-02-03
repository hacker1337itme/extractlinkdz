# extractlinkdz
extractlinkdz

HTTP Link Extractor with Crawling - Extract links with depth-based crawling

Usage:
  extractlinkdz [options] [seed_urls...]

```

Input Sources (use one):
  -url string           Make HTTP request to URL
  -file string          Read HTTP response from file
  -har string           Read from .har file
  -raw string           Raw HTTP response text
  -stdin                Read from stdin
  -crawl                Enable crawling mode (requires seed URLs)

Crawling Options:
  -depth int            Maximum crawl depth (default: 1)
  -max-pages int        Maximum pages to crawl (0 = unlimited)
  -delay duration       Delay between requests (e.g., 500ms, 2s)
  -concurrency int      Maximum concurrent requests (default: 10)
  -user-agent string    Custom User-Agent string
  -timeout duration     Timeout for HTTP requests (default: 10s)

Extraction Options:
  -rel string           Filter by relationship (next, prev, etc)
  -all                  Extract all links (headers + body)
  -headers-only         Extract only from headers (default)
  -body-only            Extract only from body
  -verbose              Show detailed information
  -format string        Output format: text, json, csv, dot
  -output string        Output file (default: stdout)
  -h, --help            Show this help

Examples:
  # Single page extraction
  extractlinkdz -url https://api.github.com/users/octocat/repos -all

  # Crawl website with depth 2
  extractlinkdz -crawl -depth 2 https://example.com

  # Crawl with custom settings
  extractlinkdz -crawl -depth 3 -max-pages 100 -delay 1s -concurrency 5 https://example.com

  # Extract from curl output
  curl -i https://example.com | extractlinkdz -stdin

  # Extract from .har file with crawling
  extractlinkdz -har network.har -crawl -depth 2

```
