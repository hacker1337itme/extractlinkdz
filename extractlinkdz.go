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
    "time"
)

// Link represents a parsed link with its relationship and parameters
type Link struct {
    URL    string
    Rel    string
    Params map[string]string
}

// HTTPResponse represents a parsed HTTP response
type HTTPResponse struct {
    Status  string
    Headers http.Header
    Body    string
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
    URL string `json:"url"`
}

type HARResponse struct {
    Status  int               `json:"status"`
    Headers []HARHeader       `json:"headers"`
    Content HARContent        `json:"content"`
}

type HARHeader struct {
    Name  string `json:"name"`
    Value string `json:"value"`
}

type HARContent struct {
    Text string `json:"text"`
}

// parseLinkHeaderAdvanced parses a Link header and returns structured Link objects
func parseLinkHeaderAdvanced(header string) []Link {
    var links []Link
    
    if header == "" {
        return links
    }
    
    entries := strings.Split(header, ",")
    
    for _, entry := range entries {
        link := Link{
            Params: make(map[string]string),
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

// ExtractAllLinks extracts all links from common header fields
func ExtractAllLinks(headers http.Header) []string {
    var allLinks []string
    
    // Check Link header
    if linkHeader := headers.Get("Link"); linkHeader != "" {
        allLinks = append(allLinks, parseSimpleLinkHeader(linkHeader)...)
    }
    
    // Check Location header
    if location := headers.Get("Location"); location != "" {
        allLinks = append(allLinks, location)
    }
    
    // Check Content-Location header
    if contentLocation := headers.Get("Content-Location"); contentLocation != "" {
        allLinks = append(allLinks, contentLocation)
    }
    
    // Check Refresh header (can contain URL)
    if refresh := headers.Get("Refresh"); refresh != "" {
        if idx := strings.Index(strings.ToLower(refresh), "url="); idx != -1 {
            url := strings.TrimSpace(refresh[idx+4:])
            allLinks = append(allLinks, url)
        }
    }
    
    return allLinks
}

// ExtractLinksByRel extracts links with specific relationship from Link header
func ExtractLinksByRel(headers http.Header, rel string) []string {
    var matchedLinks []string
    
    if linkHeader := headers.Get("Link"); linkHeader != "" {
        links := parseLinkHeaderAdvanced(linkHeader)
        
        for _, link := range links {
            if link.Rel == rel {
                matchedLinks = append(matchedLinks, link.URL)
            }
        }
    }
    
    return matchedLinks
}

// parseRawHTTP parses raw HTTP response text
func parseRawHTTP(raw string) (*HTTPResponse, error) {
    reader := bufio.NewReader(strings.NewReader(raw))
    resp := &HTTPResponse{
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
func extractLinksFromBody(body string, baseURL string) []string {
    var links []string
    
    // Extract URLs from href/src attributes
    urlRegex := regexp.MustCompile(`(href|src|action)\s*=\s*['"]([^'"]+)['"]`)
    matches := urlRegex.FindAllStringSubmatch(body, -1)
    for _, match := range matches {
        if len(match) > 2 {
            link := match[2]
            if strings.HasPrefix(link, "http://") || strings.HasPrefix(link, "https://") {
                links = append(links, link)
            } else if baseURL != "" && !strings.HasPrefix(link, "#") && !strings.HasPrefix(link, "javascript:") {
                // Resolve relative URL
                base, err := url.Parse(baseURL)
                if err == nil {
                    resolved, err := base.Parse(link)
                    if err == nil {
                        links = append(links, resolved.String())
                    }
                }
            }
        }
    }
    
    return links
}

// parseHARFile parses a .har file and extracts responses
func parseHARFile(filename string) ([]HTTPResponse, error) {
    content, err := os.ReadFile(filename)
    if err != nil {
        return nil, err
    }
    
    var har HAR
    if err := json.Unmarshal(content, &har); err != nil {
        return nil, err
    }
    
    var responses []HTTPResponse
    for _, entry := range har.Log.Entries {
        resp := HTTPResponse{
            Status:  fmt.Sprintf("HTTP/1.1 %d", entry.Response.Status),
            Headers: make(http.Header),
            Body:    entry.Response.Content.Text,
        }
        
        for _, h := range entry.Response.Headers {
            resp.Headers.Add(h.Name, h.Value)
        }
        
        responses = append(responses, resp)
    }
    
    return responses, nil
}

// fetchURL makes an HTTP request and returns the response
func fetchURL(urlStr string, timeout int) (*HTTPResponse, error) {
    client := &http.Client{
        Timeout: time.Duration(timeout) * time.Second,
    }
    
    resp, err := client.Get(urlStr)
    if err != nil {
        return nil, err
    }
    defer resp.Body.Close()
    
    body, err := io.ReadAll(resp.Body)
    if err != nil {
        return nil, err
    }
    
    httpResp := &HTTPResponse{
        Status:  resp.Status,
        Headers: resp.Header,
        Body:    string(body),
    }
    
    return httpResp, nil
}

// displayResults displays extracted links
func displayResults(links []string, verbose bool, source string) {
    if len(links) == 0 {
        fmt.Printf("No links found in %s\n", source)
        return
    }
    
    fmt.Printf("=== Links extracted from %s (%d found) ===\n", source, len(links))
    for i, link := range links {
        if verbose {
            fmt.Printf("%3d. %s\n", i+1, link)
        } else {
            fmt.Println(link)
        }
    }
}

func printUsage() {
    fmt.Println("HTTP Link Extractor - Extract links from various sources")
    fmt.Println()
    fmt.Println("Usage:")
    fmt.Println("  extractlinkdz [options]")
    fmt.Println()
    fmt.Println("Input Sources (use one):")
    fmt.Println("  -url string           Make HTTP request to URL")
    fmt.Println("  -file string          Read HTTP response from file")
    fmt.Println("  -har string           Read from .har file")
    fmt.Println("  -raw string           Raw HTTP response text")
    fmt.Println("  -stdin                Read from stdin")
    fmt.Println()
    fmt.Println("Options:")
    fmt.Println("  -rel string           Filter by relationship (next, prev, etc)")
    fmt.Println("  -all                  Extract all links (headers + body)")
    fmt.Println("  -headers-only         Extract only from headers (default)")
    fmt.Println("  -body-only            Extract only from body")
    fmt.Println("  -timeout int          Timeout in seconds for HTTP requests (default: 10)")
    fmt.Println("  -verbose              Show detailed information")
    fmt.Println("  -format string        Output format: text, json, csv")
    fmt.Println("  -output string        Output file (default: stdout)")
    fmt.Println("  -h, --help            Show this help")
    fmt.Println()
    fmt.Println("Examples:")
    fmt.Println("  # Extract from a website")
    fmt.Println("  extractlinkdz -url https://api.github.com/users/octocat/repos")
    fmt.Println()
    fmt.Println("  # Extract from curl output")
    fmt.Println("  curl -i https://example.com | extractlinkdz -stdin")
    fmt.Println()
    fmt.Println("  # Extract from browser dev tools copy")
    fmt.Println("  extractlinkdz -raw \"$(pbpaste)\"")
    fmt.Println()
    fmt.Println("  # Extract from .har file")
    fmt.Println("  extractlinkdz -har network.har")
    fmt.Println()
    fmt.Println("  # Extract from saved response")
    fmt.Println("  extractlinkdz -file response.txt")
    fmt.Println()
    fmt.Println("  # Filter by relationship")
    fmt.Println("  extractlinkdz -url https://api.github.com/users/octocat/repos -rel next")
}

func main() {
    // Input sources
    urlStr := flag.String("url", "", "URL to fetch")
    filePath := flag.String("file", "", "File containing HTTP response")
    harFile := flag.String("har", "", ".har file")
    rawHTTP := flag.String("raw", "", "Raw HTTP response text")
    useStdin := flag.Bool("stdin", false, "Read from stdin")
    
    // Options
    filterRel := flag.String("rel", "", "Filter by relationship")
    allLinks := flag.Bool("all", false, "Extract all links")
    headersOnly := flag.Bool("headers-only", false, "Extract only from headers")
    bodyOnly := flag.Bool("body-only", false, "Extract only from body")
    timeout := flag.Int("timeout", 10, "Timeout in seconds")
    verbose := flag.Bool("verbose", false, "Verbose output")
    format := flag.String("format", "text", "Output format: text, json, csv")
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
    
    // Validate input source
    inputSources := 0
    for _, source := range []string{*urlStr, *filePath, *harFile, *rawHTTP} {
        if source != "" {
            inputSources++
        }
    }
    if *useStdin {
        inputSources++
    }
    
    if inputSources == 0 {
        fmt.Println("Error: No input source specified")
        printUsage()
        os.Exit(1)
    }
    
    if inputSources > 1 {
        fmt.Println("Error: Multiple input sources specified")
        printUsage()
        os.Exit(1)
    }
    
    // Process based on input source
    var links []string
    var sourceName string
    
    switch {
    case *urlStr != "":
        sourceName = fmt.Sprintf("URL: %s", *urlStr)
        if *verbose {
            fmt.Printf("Fetching %s...\n", *urlStr)
        }
        
        resp, err := fetchURL(*urlStr, *timeout)
        if err != nil {
            fmt.Printf("Error fetching URL: %v\n", err)
            os.Exit(1)
        }
        
        links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, *urlStr)
        
    case *filePath != "":
        sourceName = fmt.Sprintf("file: %s", *filePath)
        content, err := readFromFile(*filePath)
        if err != nil {
            fmt.Printf("Error reading file: %v\n", err)
            os.Exit(1)
        }
        
        resp, err := parseRawHTTP(content)
        if err != nil {
            // Try as plain text
            resp = &HTTPResponse{Body: content}
        }
        
        links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, "")
        
    case *harFile != "":
        sourceName = fmt.Sprintf("HAR file: %s", *harFile)
        responses, err := parseHARFile(*harFile)
        if err != nil {
            fmt.Printf("Error parsing HAR file: %v\n", err)
            os.Exit(1)
        }
        
        for _, resp := range responses {
            links = append(links, extractLinks(&resp, *allLinks, *headersOnly, *bodyOnly, "")...)
        }
        
        // Remove duplicates
        links = removeDuplicates(links)
        
    case *rawHTTP != "":
        sourceName = "raw HTTP response"
        resp, err := parseRawHTTP(*rawHTTP)
        if err != nil {
            fmt.Printf("Error parsing raw HTTP: %v\n", err)
            os.Exit(1)
        }
        
        links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, "")
        
    case *useStdin:
        sourceName = "stdin"
        content, err := io.ReadAll(os.Stdin)
        if err != nil {
            fmt.Printf("Error reading from stdin: %v\n", err)
            os.Exit(1)
        }
        
        resp, err := parseRawHTTP(string(content))
        if err != nil {
            // Try as plain text
            resp = &HTTPResponse{Body: string(content)}
        }
        
        links = extractLinks(resp, *allLinks, *headersOnly, *bodyOnly, "")
    }
    
    // Apply relationship filter if specified
    if *filterRel != "" {
        var filteredLinks []string
        for _, link := range links {
            // Simple filter - in real use, you'd parse headers properly
            if strings.Contains(strings.ToLower(link), strings.ToLower(*filterRel)) {
                filteredLinks = append(filteredLinks, link)
            }
        }
        links = filteredLinks
    }
    
    // Output results
    if *outputFile != "" {
        file, err := os.Create(*outputFile)
        if err != nil {
            fmt.Printf("Error creating output file: %v\n", err)
            os.Exit(1)
        }
        defer file.Close()
        
        switch *format {
        case "json":
            encoder := json.NewEncoder(file)
            encoder.SetIndent("", "  ")
            encoder.Encode(map[string]interface{}{
                "source": sourceName,
                "count":  len(links),
                "links":  links,
            })
        case "csv":
            file.WriteString("url\n")
            for _, link := range links {
                file.WriteString(fmt.Sprintf("\"%s\"\n", strings.ReplaceAll(link, "\"", "\"\"")))
            }
        default: // text
            file.WriteString(fmt.Sprintf("Links extracted from %s:\n\n", sourceName))
            for i, link := range links {
                file.WriteString(fmt.Sprintf("%d. %s\n", i+1, link))
            }
        }
        fmt.Printf("Results written to %s\n", *outputFile)
    } else {
        displayResults(links, *verbose, sourceName)
    }
}

// extractLinks extracts links based on options
func extractLinks(resp *HTTPResponse, allLinks, headersOnly, bodyOnly bool, baseURL string) []string {
    var links []string
    
    if !bodyOnly {
        // Extract from headers
        headerLinks := ExtractAllLinks(resp.Headers)
        links = append(links, headerLinks...)
    }
    
    if (!headersOnly || allLinks) && resp.Body != "" {
        // Extract from body
        bodyLinks := extractLinksFromBody(resp.Body, baseURL)
        links = append(links, bodyLinks...)
    }
    
    // Remove duplicates
    return removeDuplicates(links)
}

// removeDuplicates removes duplicate URLs
func removeDuplicates(links []string) []string {
    seen := make(map[string]bool)
    var unique []string
    
    for _, link := range links {
        if !seen[link] {
            seen[link] = true
            unique = append(unique, link)
        }
    }
    
    return unique
}
