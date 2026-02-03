package main

import (
    "bufio"
    "encoding/json"
    "flag"
    "fmt"
    "io"
    "net/http"
    "net/url"
    "os"
    "regexp"
    "strings"
    "sync"
    "time"
)

// Link represents a parsed link with its relationship and parameters
type Link struct {
    URL     string
    Rel     string
    Params  map[string]string
    Source  string
    Depth   int
    Headers http.Header
}

// HTTPResponse represents a parsed HTTP response
type HTTPResponse struct {
    URL     string
    Status  string
    Headers http.Header
    Body    string
    Depth   int
}

// CrawlResult represents the result of a crawl
type CrawlResult struct {
    URL      string
    Depth    int
    Links    []Link
    Error    error
    Response *HTTPResponse
}

// HAR structures for parsing .har files
type HAR struct {
    Log HARLog `json:"log"`
}

type HARLog struct {
    Entries []HAREntry `json:"entries"`
}

type HAREntry struct {
    Request  HARRequest  `json:"request"`
    Response HARResponse `json:"response"`
}

type HARRequest struct {
    URL         string      `json:"url"`
    Method      string      `json:"method"`
    HTTPVersion string      `json:"httpVersion"`
    Headers     []HARHeader `json:"headers"`
    Cookies     []HARCookie `json:"cookies"`
    QueryString []HARQuery  `json:"queryString"`
}

type HARQuery struct {
    Name  string `json:"name"`
    Value string `json:"value"`
}

type HARContent struct {
    Text     string `json:"text"`
    MimeType string `json:"mimeType"`
    Size     int    `json:"size"`
    Encoding string `json:"encoding"`
}

type HARCookie struct {
    Name     string `json:"name"`
    Value    string `json:"value"`
    Path     string `json:"path"`
    Domain   string `json:"domain"`
    Expires  string `json:"expires"`
    Secure   bool   `json:"secure"`
    HTTPOnly bool   `json:"httpOnly"`
}

type HARResponse struct {
    Status      int               `json:"status"`
    StatusText  string            `json:"statusText"`
    HTTPVersion string            `json:"httpVersion"`
    Headers     []HARHeader       `json:"headers"`
    Cookies     []HARCookie       `json:"cookies"`
    Content     HARContent        `json:"content"`
    RedirectURL string            `json:"redirectURL"`
}

type HARHeader struct {
    Name  string `json:"name"`
    Value string `json:"value"`
}

// Crawler manages the crawling process
type Crawler struct {
    MaxDepth     int
    MaxPages     int
    Delay        time.Duration
    Timeout      time.Duration
    Concurrency  int
    UserAgent    string
    IncludeBody  bool
    Verbose      bool
    Visited      sync.Map
    Results      chan CrawlResult
    WaitGroup    sync.WaitGroup
    Semaphore    chan struct{}
    TotalCrawled int
    StartTime    time.Time
}

func printLogo() {
    logo := `
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║    ██╗     ██╗███╗   ██╗██╗  ██╗    ███████╗██╗  ██╗    ║
    ║    ██║     ██║████╗  ██║██║ ██╔╝    ██╔════╝╚██╗██╔╝    ║
    ║    ██║     ██║██╔██╗ ██║█████╔╝     █████╗   ╚███╔╝     ║
    ║    ██║     ██║██║╚██╗██║██╔═██╗     ██╔══╝   ██╔██╗     ║
    ║    ███████╗██║██║ ╚████║██║  ██╗    ███████╗██╔╝ ██╗    ║
    ║    ╚══════╝╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝    ╚══════╝╚═╝  ╚═╝    ║
    ║                                                          ║
    ║      ███████╗██╗  ██╗████████╗██████╗ █████╗  ██████╗   ║
    ║      ██╔════╝╚██╗██╔╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗  ║
    ║      █████╗   ╚███╔╝    ██║   ██████╔╝███████║██║   ██║  ║
    ║      ██╔══╝   ██╔██╗    ██║   ██╔══██╗██╔══██║██║   ██║  ║
    ║      ███████╗██╔╝ ██╗   ██║   ██║  ██║██║  ██║╚██████╔╝  ║
    ║      ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝   ║
    ║                                                          ║
    ║            HTTP Link Extractor & Crawler                 ║
    ║            Version 2.0 | by extractlinkdz root           ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    `
    fmt.Println(logo)
}

func printSimpleLogo() {
    logo := `
    ╔═══════════════════════════════════════╗
    ║  🔗 𝓛𝓲𝓷𝓴𝓔𝔁𝓽𝓻𝓪𝓬𝓽𝓸𝓻 𝓓𝓩 🔗                ║
    ║  ➤ HTTP Link Extraction Tool          ║
    ║  ➤ v2.0 | Depth-aware Crawler         ║
    ╚═══════════════════════════════════════╝
    `
    fmt.Println(logo)
}

// parseLinkHeaderAdvanced parses a Link header and returns structured Link objects
func parseLinkHeaderAdvanced(header, source string, depth int, headers http.Header) []Link {
    var links []Link

    if header == "" {
        return links
    }

    entries := strings.Split(header, ",")

    for _, entry := range entries {
        link := Link{
            Params:  make(map[string]string),
            Source:  source,
            Depth:   depth,
            Headers: headers,
        }

        // Extract URL between < and >
        start := strings.Index(entry, "<")
        end := strings.Index(entry, ">")

        if start == -1 || end == -1 || start >= end {
            continue
        }

        link.URL = strings.TrimSpace(entry[start+1 : end])

        // Extract parameters after the URL
        paramsStr := strings.TrimSpace(entry[end+1:])
        params := strings.Split(paramsStr, ";")

        for _, param := range params {
            param = strings.TrimSpace(param)
            if param == "" {
                continue
            }

            // Split key=value
            parts := strings.SplitN(param, "=", 2)
            if len(parts) == 2 {
                key := strings.TrimSpace(parts[0])
                value := strings.Trim(parts[1], `"`)

                if key == "rel" {
                    link.Rel = value
                } else {
                    link.Params[key] = value
                }
            } else if len(parts) == 1 {
                key := strings.TrimSpace(parts[0])
                link.Params[key] = ""
            }
        }

        links = append(links, link)
    }

    return links
}

// parseSimpleLinkHeader extracts just URLs from a Link header
func parseSimpleLinkHeader(header string) []string {
    var links []string

    if header == "" {
        return links
    }

    entries := strings.Split(header, ",")
    for _, entry := range entries {
        start := strings.Index(entry, "<")
        end := strings.Index(entry, ">")

        if start != -1 && end != -1 && start < end {
            url := entry[start+1 : end]
            links = append(links, strings.TrimSpace(url))
        }
    }

    return links
}

// ExtractAllLinksFromHeaders extracts all links from ALL header fields
func ExtractAllLinksFromHeaders(headers http.Header, source string, depth int) []Link {
    var allLinks []Link

    // Check ALL headers for URLs, not just known ones
    for headerName, values := range headers {
        for _, value := range values {
            // Check for URLs in any header
            urls := extractURLsFromString(value)
            for _, urlStr := range urls {
                link := Link{
                    URL:     urlStr,
                    Source:  source,
                    Depth:   depth,
                    Headers: headers,
                    Params:  make(map[string]string),
                }
                link.Params["header"] = headerName
                allLinks = append(allLinks, link)
            }

            // Special parsing for Link header
            if strings.EqualFold(headerName, "Link") {
                parsedLinks := parseLinkHeaderAdvanced(value, source, depth, headers)
                allLinks = append(allLinks, parsedLinks...)
            }
        }
    }

    // Also check for specific known headers
    specificHeaders := []string{"Location", "Content-Location", "Refresh", "X-Github-Media-Type"}
    for _, hdr := range specificHeaders {
        if value := headers.Get(hdr); value != "" {
            if urls := extractURLsFromString(value); len(urls) > 0 {
                for _, urlStr := range urls {
                    link := Link{
                        URL:     urlStr,
                        Source:  source,
                        Depth:   depth,
                        Headers: headers,
                        Params:  make(map[string]string),
                    }
                    link.Params["header"] = hdr
                    allLinks = append(allLinks, link)
                }
            }
        }
    }

    return allLinks
}

// extractURLsFromString extracts URLs from any string
func extractURLsFromString(text string) []string {
    var urls []string
    // More comprehensive URL regex
    urlRegex := regexp.MustCompile(`(https?://[^\s<>"']+|www\.[^\s<>"']+|[a-z0-9.-]+\.[a-z]{2,}/[^\s<>"']*)`)
    matches := urlRegex.FindAllString(text, -1)
    for _, match := range matches {
        if !strings.HasPrefix(match, "http://") && !strings.HasPrefix(match, "https://") {
            match = "https://" + match
        }
        urls = append(urls, match)
    }
    return urls
}

// ExtractLinksByRel extracts links with specific relationship from Link header
func ExtractLinksByRel(headers http.Header, rel string, source string, depth int) []Link {
    var matchedLinks []Link

    if linkHeader := headers.Get("Link"); linkHeader != "" {
        links := parseLinkHeaderAdvanced(linkHeader, source, depth, headers)

        for _, link := range links {
            if link.Rel == rel {
                matchedLinks = append(matchedLinks, link)
            }
        }
    }

    return matchedLinks
}

// parseRawHTTP parses raw HTTP response text
func parseRawHTTP(raw, source string) (*HTTPResponse, error) {
    reader := bufio.NewReader(strings.NewReader(raw))
    resp := &HTTPResponse{
        URL:     source,
        Headers: make(http.Header),
    }

    // Parse status line
    statusLine, err := reader.ReadString('\n')
    if err != nil {
        return nil, fmt.Errorf("failed to read status line: %v", err)
    }
    resp.Status = strings.TrimSpace(statusLine)

    // Parse headers
    for {
        line, err := reader.ReadString('\n')
        if err != nil || line == "\r\n" || line == "\n" {
            break
        }

        line = strings.TrimSpace(line)
        if line == "" {
            break
        }

        parts := strings.SplitN(line, ":", 2)
        if len(parts) == 2 {
            key := strings.TrimSpace(parts[0])
            value := strings.TrimSpace(parts[1])
            resp.Headers.Add(key, value)
        }
    }

    // Read body
    body, err := io.ReadAll(reader)
    if err == nil {
        resp.Body = string(body)
    }

    return resp, nil
}

// readFromFile reads content from a file
func readFromFile(filename string) (string, error) {
    content, err := os.ReadFile(filename)
    if err != nil {
        return "", err
    }
    return string(content), nil
}

// extractLinksFromBody extracts links from HTML/JSON body
func extractLinksFromBody(body, baseURL, source string, depth int) []Link {
    var links []Link

    // More comprehensive regex for extracting URLs
    patterns := []*regexp.Regexp{
        regexp.MustCompile(`(href|src|action|cite|data|background|poster|profile)\s*=\s*['"]([^'"]+)['"]`),
        regexp.MustCompile(`url\s*\(\s*['"]?([^'")\s]+)['"]?\s*\)`),
        regexp.MustCompile(`(https?://[^\s<>"']+)`),
        regexp.MustCompile(`"url"\s*:\s*"([^"]+)"`),
        regexp.MustCompile(`'url'\s*:\s*'([^']+)'`),
    }

    allMatches := make(map[string]bool)

    for _, pattern := range patterns {
        matches := pattern.FindAllStringSubmatch(body, -1)
        for _, match := range matches {
            var linkURL string
            if len(match) > 2 {
                linkURL = match[2]
            } else if len(match) > 1 {
                linkURL = match[1]
            }

            if linkURL != "" && !allMatches[linkURL] {
                allMatches[linkURL] = true

                // Resolve relative URLs
                if !strings.HasPrefix(linkURL, "http://") && !strings.HasPrefix(linkURL, "https://") {
                    if baseURL != "" && !strings.HasPrefix(linkURL, "#") &&
                        !strings.HasPrefix(linkURL, "javascript:") &&
                        !strings.HasPrefix(linkURL, "mailto:") &&
                        !strings.HasPrefix(linkURL, "tel:") &&
                        !strings.HasPrefix(linkURL, "data:") {

                        base, err := url.Parse(baseURL)
                        if err == nil {
                            resolved, err := base.Parse(linkURL)
                            if err == nil {
                                linkURL = resolved.String()
                            }
                        }
                    } else {
                        continue // Skip non-absolute URLs without base
                    }
                }

                link := Link{
                    URL:    linkURL,
                    Source: source,
                    Depth:  depth,
                    Params: make(map[string]string),
                }
                link.Params["source"] = "body"
                link.Params["pattern"] = pattern.String()
                links = append(links, link)
            }
        }
    }

    return links
}

// normalizeHTTPVersion normalizes HTTP version strings
func normalizeHTTPVersion(version string) string {
    version = strings.TrimSpace(version)
    version = strings.ToUpper(version)

    // Map common variations
    switch version {
    case "HTTP/1.0", "HTTP/1", "1.0", "1":
        return "HTTP/1.0"
    case "HTTP/1.1", "1.1":
        return "HTTP/1.1"
    case "HTTP/2", "HTTP/2.0", "2", "2.0":
        return "HTTP/2"
    case "HTTP/3", "HTTP/3.0", "3", "3.0":
        return "HTTP/3"
    default:
        // Try to extract version from string
        if strings.Contains(version, "HTTP/") {
            return version
        }
        return "HTTP/1.1"
    }
}

// parseHARFile parses a .har file and extracts responses
func parseHARFile(filename string, verbose bool) ([]HTTPResponse, error) {
    content, err := os.ReadFile(filename)
    if err != nil {
        return nil, err
    }

    var har HAR
    if err := json.Unmarshal(content, &har); err != nil {
        return nil, err
    }

    var responses []HTTPResponse
    successCount := 0
    errorCount := 0

    for i, entry := range har.Log.Entries {
        // Check for empty or invalid entry
        if entry.Response.Status == 0 {
            if verbose {
                fmt.Printf("[WARN] Entry %d has invalid response, skipping\n", i)
            }
            errorCount++
            continue
        }

        // Build full URL
        fullURL := entry.Request.URL

        // Handle query string if present
        if entry.Request.QueryString != nil && len(entry.Request.QueryString) > 0 {
            baseURL, err := url.Parse(fullURL)
            if err == nil {
                query := url.Values{}
                for _, q := range entry.Request.QueryString {
                    if q.Name != "" {
                        query.Add(q.Name, q.Value)
                    }
                }
                if len(query) > 0 {
                    baseURL.RawQuery = query.Encode()
                    fullURL = baseURL.String()
                }
            }
        }

        // Determine HTTP version
        httpVersion := "HTTP/1.1"
        if entry.Response.HTTPVersion != "" {
            httpVersion = entry.Response.HTTPVersion
        } else if entry.Request.HTTPVersion != "" {
            httpVersion = entry.Request.HTTPVersion
        }

        // Normalize HTTP version
        httpVersion = normalizeHTTPVersion(httpVersion)

        // Build status line
        statusText := entry.Response.StatusText
        if statusText == "" {
            // Common status texts
            switch entry.Response.Status {
            case 200:
                statusText = "OK"
            case 201:
                statusText = "Created"
            case 204:
                statusText = "No Content"
            case 301:
                statusText = "Moved Permanently"
            case 302:
                statusText = "Found"
            case 304:
                statusText = "Not Modified"
            case 400:
                statusText = "Bad Request"
            case 401:
                statusText = "Unauthorized"
            case 403:
                statusText = "Forbidden"
            case 404:
                statusText = "Not Found"
            case 500:
                statusText = "Internal Server Error"
            case 502:
                statusText = "Bad Gateway"
            case 503:
                statusText = "Service Unavailable"
            default:
                statusText = "Unknown"
            }
        }

        statusLine := fmt.Sprintf("%s %d %s", httpVersion, entry.Response.Status, statusText)

        resp := HTTPResponse{
            URL:     fullURL,
            Status:  statusLine,
            Headers: make(http.Header),
            Body:    entry.Response.Content.Text,
            Depth:   0,
        }

        // Process headers
        for _, h := range entry.Response.Headers {
            if h.Name != "" {
                resp.Headers.Add(h.Name, h.Value)
            }
        }

        // Process cookies
        if entry.Response.Cookies != nil && len(entry.Response.Cookies) > 0 {
            for _, cookie := range entry.Response.Cookies {
                if cookie.Name == "" {
                    continue
                }
                cookieStr := fmt.Sprintf("%s=%s", cookie.Name, cookie.Value)
                if cookie.Path != "" {
                    cookieStr += fmt.Sprintf("; Path=%s", cookie.Path)
                }
                if cookie.Domain != "" {
                    cookieStr += fmt.Sprintf("; Domain=%s", cookie.Domain)
                }
                if cookie.Expires != "" {
                    cookieStr += fmt.Sprintf("; Expires=%s", cookie.Expires)
                }
                if cookie.Secure {
                    cookieStr += "; Secure"
                }
                if cookie.HTTPOnly {
                    cookieStr += "; HttpOnly"
                }
                resp.Headers.Add("Set-Cookie", cookieStr)
            }
        }

        // Set default headers if missing
        if entry.Response.Content.MimeType != "" && resp.Headers.Get("Content-Type") == "" {
            resp.Headers.Set("Content-Type", entry.Response.Content.MimeType)
        }

        if resp.Body != "" && resp.Headers.Get("Content-Length") == "" {
            resp.Headers.Set("Content-Length", fmt.Sprintf("%d", len(resp.Body)))
        }

        // Add request method as custom header for reference
        if entry.Request.Method != "" {
            resp.Headers.Set("X-Request-Method", entry.Request.Method)
        }

        // Add redirect location if present
        if entry.Response.RedirectURL != "" {
            resp.Headers.Set("Location", entry.Response.RedirectURL)
        }

        responses = append(responses, resp)
        successCount++
    }

    if verbose {
        fmt.Printf("[INFO] Successfully parsed %d responses from HAR file\n", successCount)
        if errorCount > 0 {
            fmt.Printf("[WARN] Skipped %d invalid entries\n", errorCount)
        }
    }

    return responses, nil
}

// fetchURL makes an HTTP request and returns the response
func fetchURL(urlStr string, timeout time.Duration, userAgent string) (*HTTPResponse, error) {
    client := &http.Client{
        Timeout: timeout,
    }

    req, err := http.NewRequest("GET", urlStr, nil)
    if err != nil {
        return nil, err
    }

    if userAgent != "" {
        req.Header.Set("User-Agent", userAgent)
    }

    resp, err := client.Do(req)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()

    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }

    httpResp := &HTTPResponse{
        URL:     urlStr,
        Status:  resp.Status,
        Headers: resp.Header,
        Body:    string(body),
    }

    return httpResp, nil
}

// NewCrawler creates a new crawler instance
func NewCrawler(maxDepth, maxPages, concurrency int, delay, timeout time.Duration, userAgent string, verbose bool) *Crawler {
    return &Crawler{
        MaxDepth:    maxDepth,
        MaxPages:    maxPages,
        Delay:       delay,
        Timeout:     timeout,
        Concurrency: concurrency,
        UserAgent:   userAgent,
        Verbose:     verbose,
        Results:     make(chan CrawlResult, 100),
        Semaphore:   make(chan struct{}, concurrency),
        StartTime:   time.Now(),
    }
}

// Crawl starts crawling from a seed URL
func (c *Crawler) Crawl(seedURL string, depth int, includeBody bool) {
    c.WaitGroup.Add(1)
    go c.crawlPage(seedURL, depth, includeBody)
}

// crawlPage crawls a single page
func (c *Crawler) crawlPage(urlStr string, depth int, includeBody bool) {
    defer c.WaitGroup.Done()

    // Check if we've visited this URL
    if _, visited := c.Visited.Load(urlStr); visited {
        return
    }
    c.Visited.Store(urlStr, true)

    // Check limits
    c.TotalCrawled++
    if c.MaxPages > 0 && c.TotalCrawled > c.MaxPages {
        return
    }

    // Acquire semaphore
    c.Semaphore <- struct{}{}
    defer func() { <-c.Semaphore }()

    // Rate limiting
    if c.Delay > 0 {
        time.Sleep(c.Delay)
    }

    if c.Verbose {
        fmt.Printf("[%d/%d] Crawling depth %d: %s\n", c.TotalCrawled, c.MaxPages, depth, urlStr)
    }

    // Fetch the page
    resp, err := fetchURL(urlStr, c.Timeout, c.UserAgent)
    if err != nil {
        c.Results <- CrawlResult{
            URL:   urlStr,
            Depth: depth,
            Error: err,
        }
        return
    }

    // Extract links
    var allLinks []Link

    // Extract from headers
    headerLinks := ExtractAllLinksFromHeaders(resp.Headers, urlStr, depth)
    allLinks = append(allLinks, headerLinks...)

    // Extract from body if requested
    if includeBody && resp.Body != "" {
        bodyLinks := extractLinksFromBody(resp.Body, urlStr, urlStr, depth)
        allLinks = append(allLinks, bodyLinks...)
    }

    // Send result
    c.Results <- CrawlResult{
        URL:      urlStr,
        Depth:    depth,
        Links:    allLinks,
        Response: resp,
    }

    // Recursively crawl found links
    if depth < c.MaxDepth {
        for _, link := range allLinks {
            // Only crawl HTTP/HTTPS links
            if strings.HasPrefix(link.URL, "http://") || strings.HasPrefix(link.URL, "https://") {
                c.WaitGroup.Add(1)
                go c.crawlPage(link.URL, depth+1, includeBody)
            }
        }
    }
}

// StartCrawling starts the crawling process
func (c *Crawler) StartCrawling(seedURLs []string, includeBody bool) {
    for _, seedURL := range seedURLs {
        c.Crawl(seedURL, 0, includeBody)
    }

    // Start a goroutine to wait for all crawls to complete
    go func() {
        c.WaitGroup.Wait()
        close(c.Results)
    }()
}

// displayLinks displays extracted links in single page mode
func displayLinks(links []Link, verbose bool, sourceName string) {
    if len(links) == 0 {
        fmt.Printf("No links found in %s\n", sourceName)
        return
    }

    fmt.Printf("=== Links extracted from %s (%d found) ===\n", sourceName, len(links))
    for i, link := range links {
        if verbose {
            fmt.Printf("%3d. %s", i+1, link.URL)
            if link.Rel != "" {
                fmt.Printf(" [Rel:%s]", link.Rel)
            }
            if len(link.Params) > 0 {
                fmt.Printf(" [Params:%v]", link.Params)
            }
            fmt.Println()
        } else {
            fmt.Println(link.URL)
        }
    }
}

// printCrawlSummary prints a summary of the crawl
func printCrawlSummary(results []CrawlResult, crawler *Crawler) {
    fmt.Printf("\n=== Crawl Summary ===\n")
    fmt.Printf("Total URLs crawled: %d\n", crawler.TotalCrawled)
    fmt.Printf("Max depth: %d\n", crawler.MaxDepth)
    fmt.Printf("Total links found: %d\n", len(results))
    fmt.Printf("Time taken: %v\n", time.Since(crawler.StartTime))

    // Group by depth
    depthCount := make(map[int]int)
    errorCount := 0
    for _, result := range results {
        depthCount[result.Depth]++
        if result.Error != nil {
            errorCount++
        }
    }

    fmt.Printf("\nDepth distribution:\n")
    for depth := 0; depth <= crawler.MaxDepth; depth++ {
        if count, ok := depthCount[depth]; ok {
            fmt.Printf("  Depth %d: %d URLs\n", depth, count)
        }
    }

    if errorCount > 0 {
        fmt.Printf("\nErrors: %d\n", errorCount)
    }

    // Count unique domains
    domains := make(map[string]int)
    for _, result := range results {
        for _, link := range result.Links {
            if u, err := url.Parse(link.URL); err == nil {
                domains[u.Host]++
            }
        }
    }

    if len(domains) > 0 {
        fmt.Printf("\nUnique domains: %d\n", len(domains))
    }
}

func printUsage() {
    fmt.Println("HTTP Link Extractor with Crawling - Extract links with depth-based crawling")
    fmt.Println()
    fmt.Println("Usage:")
    fmt.Println("  extractlinkdz [options] [seed_urls...]")
    fmt.Println()
    fmt.Println("Input Sources (use one):")
    fmt.Println("  -url string           Make HTTP request to URL")
    fmt.Println("  -file string          Read HTTP response from file")
    fmt.Println("  -har string           Read from .har file")
    fmt.Println("  -raw string           Raw HTTP response text")
    fmt.Println("  -stdin                Read from stdin")
    fmt.Println("  -crawl                Enable crawling mode (requires seed URLs)")
    fmt.Println()
    fmt.Println("Crawling Options:")
    fmt.Println("  -depth int            Maximum crawl depth (default: 1)")
    fmt.Println("  -max-pages int        Maximum pages to crawl (0 = unlimited)")
    fmt.Println("  -delay duration       Delay between requests (e.g., 500ms, 2s)")
    fmt.Println("  -concurrency int      Maximum concurrent requests (default: 10)")
    fmt.Println("  -user-agent string    Custom User-Agent string")
    fmt.Println("  -timeout duration     Timeout for HTTP requests (default: 10s)")
    fmt.Println()
    fmt.Println("Extraction Options:")
    fmt.Println("  -rel string           Filter by relationship (next, prev, etc)")
    fmt.Println("  -all                  Extract all links (headers + body)")
    fmt.Println("  -headers-only         Extract only from headers (default)")
    fmt.Println("  -body-only            Extract only from body")
    fmt.Println("  -verbose              Show detailed information")
    fmt.Println("  -format string        Output format: text, json, csv, dot")
    fmt.Println("  -output string        Output file (default: stdout)")
    fmt.Println("  -h, --help            Show this help")
    fmt.Println()
    fmt.Println("Examples:")
    fmt.Println("  # Single page extraction")
    fmt.Println("  extractlinkdz -url https://api.github.com/users/octocat/repos -all")
    fmt.Println()
    fmt.Println("  # Crawl website with depth 2")
    fmt.Println("  extractlinkdz -crawl -depth 2 https://example.com")
    fmt.Println()
    fmt.Println("  # Crawl with custom settings")
    fmt.Println("  extractlinkdz -crawl -depth 3 -max-pages 100 -delay 1s -concurrency 5 https://example.com")
    fmt.Println()
    fmt.Println("  # Extract from curl output")
    fmt.Println("  curl -i https://example.com | extractlinkdz -stdin")
    fmt.Println()
    fmt.Println("  # Extract from .har file with crawling")
    fmt.Println("  extractlinkdz -har network.har -crawl -depth 2")
}

func main() {
    // Input sources
    urlStr := flag.String("url", "", "URL to fetch")
    filePath := flag.String("file", "", "File containing HTTP response")
    harFile := flag.String("har", "", ".har file")
    rawHTTP := flag.String("raw", "", "Raw HTTP response text")
    useStdin := flag.Bool("stdin", false, "Read from stdin")
    crawlMode := flag.Bool("crawl", false, "Enable crawling mode")

    // Crawling options
    depth := flag.Int("depth", 1, "Maximum crawl depth")
    maxPages := flag.Int("max-pages", 0, "Maximum pages to crawl (0 = unlimited)")
    delay := flag.Duration("delay", 0, "Delay between requests")
    concurrency := flag.Int("concurrency", 10, "Maximum concurrent requests")
    userAgent := flag.String("user-agent", "LinkExtractor/1.0", "User-Agent string")
    timeout := flag.Duration("timeout", 10*time.Second, "Timeout for HTTP requests")

    // Extraction options
    filterRel := flag.String("rel", "", "Filter by relationship")
    allLinks := flag.Bool("all", false, "Extract all links")
    headersOnly := flag.Bool("headers-only", false, "Extract only from headers")
    bodyOnly := flag.Bool("body-only", false, "Extract only from body")
    verbose := flag.Bool("verbose", false, "Verbose output")
    format := flag.String("format", "text", "Output format: text, json, csv, dot")
    outputFile := flag.String("output", "", "Output file")

    flag.Usage = func() {
        printUsage()
    }

    flag.Parse()

    // Check for help
    if len(os.Args) > 1 && (os.Args[1] == "-h" || os.Args[1] == "--help") {
        printUsage()
        os.Exit(0)
    }

    // Show logo only if not help command and not verbose animated mode
    if len(os.Args) > 1 && os.Args[1] != "-h" && os.Args[1] != "--help" {
        if *verbose && !*crawlMode {
            // Don't show animated logo for now to avoid complexity
            printSimpleLogo()
        } else if !*verbose {
            printSimpleLogo()
            fmt.Println()
        }
    }

    // Process based on input source
    var allLinksFound []Link
    var seedURLs []string

    // Get seed URLs from command line arguments
    seedURLs = flag.Args()

    if *crawlMode && len(seedURLs) == 0 && *urlStr == "" && *harFile == "" {
        fmt.Println("Error: Crawling mode requires seed URLs")
        printUsage()
        os.Exit(1)
    }

    // If crawl mode, start crawling
    if *crawlMode {
        if *verbose {
            fmt.Println("Starting crawl...")
            fmt.Printf("Seed URLs: %v\n", seedURLs)
            fmt.Printf("Max depth: %d\n", *depth)
            fmt.Printf("Max pages: %d\n", *maxPages)
            fmt.Printf("Concurrency: %d\n", *concurrency)
        }

        // Add single URL from -url flag if provided
        if *urlStr != "" {
            seedURLs = append(seedURLs, *urlStr)
        }

        // Handle HAR file in crawl mode
        if *harFile != "" {
            responses, err := parseHARFile(*harFile, *verbose)
            if err != nil {
                fmt.Printf("Error parsing HAR file: %v\n", err)
                os.Exit(1)
            }

            for _, resp := range responses {
                seedURLs = append(seedURLs, resp.URL)

                // Extract links from HAR response
                links := extractLinks(&resp, *allLinks, *headersOnly, *bodyOnly, resp.URL, 0)
                allLinksFound = append(allLinksFound, links...)
            }
        }

        if len(seedURLs) == 0 {
            fmt.Println("Error: No seed URLs provided for crawling")
            os.Exit(1)
        }

        // Create crawler and start
        crawler := NewCrawler(*depth, *maxPages, *concurrency, *delay, *timeout, *userAgent, *verbose)
        crawler.StartCrawling(seedURLs, *allLinks || !*headersOnly)

        // Collect results
        var crawlResults []CrawlResult
        for result := range crawler.Results {
            crawlResults = append(crawlResults, result)
            for _, link := range result.Links {
                allLinksFound = append(allLinksFound, link)
            }

            if result.Error != nil && *verbose {
                fmt.Printf("Error crawling %s: %v\n", result.URL, result.Error)
            }
        }

        // Print summary
        printCrawlSummary(crawlResults, crawler)

    } else {
        // Single page extraction mode
        var links []Link
        var sourceName string

        switch {
        case *urlStr != "":
            sourceName = fmt.Sprintf("URL: %s", *urlStr)
            if *verbose {
                fmt.Printf("Fetching %s...\n", *urlStr)
            }

            resp, err := fetchURL(*urlStr, *timeout, *userAgent)
            if err != nil {
                fmt.Printf("Error fetching URL: %v\n", err)
                os.Exit(1)
            }

            links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, *urlStr, 0)

        case *filePath != "":
            sourceName = fmt.Sprintf("file: %s", *filePath)
            content, err := readFromFile(*filePath)
            if err != nil {
                fmt.Printf("Error reading file: %v\n", err)
                os.Exit(1)
            }

            resp, err := parseRawHTTP(content, *filePath)
            if err != nil {
                // Try as plain text
                resp = &HTTPResponse{Body: content, URL: *filePath}
            }

            links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, *filePath, 0)

        case *harFile != "":
            sourceName = fmt.Sprintf("HAR file: %s", *harFile)
            responses, err := parseHARFile(*harFile, *verbose)
            if err != nil {
                fmt.Printf("Error parsing HAR file: %v\n", err)
                os.Exit(1)
            }

            for _, resp := range responses {
                links = append(links, extractLinks(&resp, *allLinks, *headersOnly, *bodyOnly, resp.URL, 0)...)
            }

        case *rawHTTP != "":
            sourceName = "raw HTTP response"
            resp, err := parseRawHTTP(*rawHTTP, "raw")
            if err != nil {
                fmt.Printf("Error parsing raw HTTP: %v\n", err)
                os.Exit(1)
            }

            links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, "raw", 0)

        case *useStdin:
            sourceName = "stdin"
            content, err := io.ReadAll(os.Stdin)
            if err != nil {
                fmt.Printf("Error reading from stdin: %v\n", err)
                os.Exit(1)
            }

            resp, err := parseRawHTTP(string(content), "stdin")
            if err != nil {
                // Try as plain text
                resp = &HTTPResponse{Body: string(content), URL: "stdin"}
            }

            links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, "stdin", 0)

        default:
            fmt.Println("Error: No input source specified")
            printUsage()
            os.Exit(1)
        }

        // Display results immediately in non-crawl mode
        if !*crawlMode && *outputFile == "" {
            displayLinks(links, *verbose, sourceName)
        }

        allLinksFound = links
    }

    // Apply relationship filter if specified
    if *filterRel != "" {
        var filteredLinks []Link
        for _, link := range allLinksFound {
            if link.Rel == *filterRel {
                filteredLinks = append(filteredLinks, link)
            }
        }
        allLinksFound = filteredLinks
    }

    // Remove duplicates while preserving structure
    allLinksFound = removeDuplicateLinks(allLinksFound)

    // Output results
    outputWriter := os.Stdout
    if *outputFile != "" {
        file, err := os.Create(*outputFile)
        if err != nil {
            fmt.Printf("Error creating output file: %v\n", err)
            os.Exit(1)
        }
        defer file.Close()
        outputWriter = file
    }

    // Output in specified format
    switch *format {
    case "json":
        encoder := json.NewEncoder(outputWriter)
        encoder.SetIndent("", "  ")
        // Convert links to map for JSON output
        linksData := make([]map[string]interface{}, len(allLinksFound))
        for i, link := range allLinksFound {
            linksData[i] = map[string]interface{}{
                "url":    link.URL,
                "rel":    link.Rel,
                "source": link.Source,
                "depth":  link.Depth,
                "params": link.Params,
            }
        }
        encoder.Encode(map[string]interface{}{
            "links": linksData,
            "count": len(allLinksFound),
        })

    case "csv":
        outputWriter.WriteString("url,rel,source,depth,params\n")
        for _, link := range allLinksFound {
            paramsStr, _ := json.Marshal(link.Params)
            outputWriter.WriteString(fmt.Sprintf("\"%s\",\"%s\",\"%s\",%d,\"%s\"\n",
                strings.ReplaceAll(link.URL, "\"", "\"\""),
                link.Rel,
                strings.ReplaceAll(link.Source, "\"", "\"\""),
                link.Depth,
                strings.ReplaceAll(string(paramsStr), "\"", "\"\"")))
        }

    case "dot":
        // Generate Graphviz DOT format for visualization
        outputWriter.WriteString("digraph LinkGraph {\n")
        outputWriter.WriteString("  rankdir=LR;\n")
        outputWriter.WriteString("  node [shape=box];\n\n")

        nodes := make(map[string]bool)
        for _, link := range allLinksFound {
            srcID := strings.ReplaceAll(link.Source, ".", "_")
            dstID := strings.ReplaceAll(link.URL, ".", "_")

            if !nodes[srcID] {
                outputWriter.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\"];\n", srcID, link.Source))
                nodes[srcID] = true
            }

            if !nodes[dstID] && link.URL != "" {
                outputWriter.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\", color=blue];\n", dstID, link.URL))
                nodes[dstID] = true
            }

            if link.URL != "" {
                relLabel := ""
                if link.Rel != "" {
                    relLabel = fmt.Sprintf("[label=\"%s\"]", link.Rel)
                }
                outputWriter.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" %s;\n", srcID, dstID, relLabel))
            }
        }
        outputWriter.WriteString("}\n")

    default: // text
        if *verbose && *outputFile == "" {
            outputWriter.WriteString(fmt.Sprintf("=== Links Extracted (%d found) ===\n\n", len(allLinksFound)))
            for i, link := range allLinksFound {
                outputWriter.WriteString(fmt.Sprintf("%d. URL: %s\n", i+1, link.URL))
                outputWriter.WriteString(fmt.Sprintf("   Source: %s\n", link.Source))
                outputWriter.WriteString(fmt.Sprintf("   Depth: %d\n", link.Depth))
                if link.Rel != "" {
                    outputWriter.WriteString(fmt.Sprintf("   Relationship: %s\n", link.Rel))
                }
                if len(link.Params) > 0 {
                    outputWriter.WriteString(fmt.Sprintf("   Parameters: %v\n", link.Params))
                }
                outputWriter.WriteString("\n")
            }
        } else {
            for _, link := range allLinksFound {
                outputWriter.WriteString(fmt.Sprintf("%s\n", link.URL))
            }
        }
    }

    if *outputFile != "" {
        fmt.Printf("Results written to %s\n", *outputFile)
    }
}

// extractLinks extracts links based on options
func extractLinks(resp *HTTPResponse, allLinks, headersOnly, bodyOnly bool, baseURL string, depth int) []Link {
    var links []Link

    if !bodyOnly {
        // Extract from headers
        headerLinks := ExtractAllLinksFromHeaders(resp.Headers, baseURL, depth)
        links = append(links, headerLinks...)
    }

    if (!headersOnly || allLinks) && resp.Body != "" {
        // Extract from body
        bodyLinks := extractLinksFromBody(resp.Body, baseURL, baseURL, depth)
        links = append(links, bodyLinks...)
    }

    return links
}

// removeDuplicateLinks removes duplicate URLs while preserving structure
func removeDuplicateLinks(links []Link) []Link {
    seen := make(map[string]bool)
    var unique []Link

    for _, link := range links {
        if !seen[link.URL] {
            seen[link.URL] = true
            unique = append(unique, link)
        }
    }

    return unique
}
