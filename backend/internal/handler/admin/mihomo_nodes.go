package admin

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultMihomoControllerURL = "http://mihomo:9090"
	defaultMihomoSelectorName  = "节点选择"
	defaultMihomoProxyID       = int64(1)
	maxMihomoResponseBytes     = 2 << 20
)

// MihomoNode is the secret-free subset of a Mihomo proxy entry exposed to the
// administrator UI. Credentials and endpoint details are deliberately omitted.
type MihomoNode struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	IsAvailable bool   `json:"is_available"`
	IsSelected  bool   `json:"is_selected"`
}

type MihomoNodesResponse struct {
	Selector string       `json:"selector"`
	Current  string       `json:"current"`
	Nodes    []MihomoNode `json:"nodes"`
}

type mihomoProxyEntry struct {
	Name  string   `json:"name"`
	Type  string   `json:"type"`
	Now   string   `json:"now"`
	All   []string `json:"all"`
	Alive *bool    `json:"alive"`
}

type mihomoNodeClient struct {
	client       *http.Client
	baseURL      string
	secret       string
	selectorName string
	proxyID      int64
}

func newMihomoNodeClient() *mihomoNodeClient {
	baseURL := strings.TrimRight(strings.TrimSpace(os.Getenv("MIHOMO_CONTROLLER_URL")), "/")
	if baseURL == "" {
		baseURL = defaultMihomoControllerURL
	}

	selectorName := strings.TrimSpace(os.Getenv("MIHOMO_SELECTOR_NAME"))
	if selectorName == "" {
		selectorName = defaultMihomoSelectorName
	}

	proxyID := defaultMihomoProxyID
	if raw := strings.TrimSpace(os.Getenv("MIHOMO_PROXY_ID")); raw != "" {
		if parsed, err := strconv.ParseInt(raw, 10, 64); err == nil && parsed > 0 {
			proxyID = parsed
		}
	}

	return &mihomoNodeClient{
		client:       &http.Client{Timeout: 8 * time.Second},
		baseURL:      baseURL,
		secret:       strings.TrimSpace(os.Getenv("MIHOMO_CONTROLLER_SECRET")),
		selectorName: selectorName,
		proxyID:      proxyID,
	}
}

func (c *mihomoNodeClient) isConfiguredProxy(proxyID int64) bool {
	return c != nil && proxyID == c.proxyID
}

func (c *mihomoNodeClient) ListNodes(ctx context.Context) (*MihomoNodesResponse, error) {
	entries, err := c.getEntries(ctx)
	if err != nil {
		return nil, err
	}

	selectorName := c.selectorName
	selector, ok := entries[selectorName]
	if !ok || !isSelectorEntry(selector) {
		for name, candidate := range entries {
			if isSelectorEntry(candidate) {
				selectorName = name
				selector = candidate
				ok = true
				break
			}
		}
	}
	if !ok {
		return nil, fmt.Errorf("mihomo selector %q not found", c.selectorName)
	}

	current := selector.Now
	nodes := make([]MihomoNode, 0, len(selector.All))
	for _, name := range selector.All {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		entry, exists := entries[name]
		nodeType := "unknown"
		available := exists
		if exists {
			nodeType = entry.Type
			available = entry.IsAvailable()
		}
		nodes = append(nodes, MihomoNode{
			Name:        name,
			Type:        nodeType,
			IsAvailable: available,
			IsSelected:  name == current,
		})
	}

	return &MihomoNodesResponse{
		Selector: selectorName,
		Current:  current,
		Nodes:    nodes,
	}, nil
}

func (c *mihomoNodeClient) SelectNode(ctx context.Context, name string) (*MihomoNodesResponse, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, fmt.Errorf("node name is required")
	}

	available, err := c.ListNodes(ctx)
	if err != nil {
		return nil, err
	}
	allowed := false
	for _, node := range available.Nodes {
		if node.Name == name && node.IsAvailable {
			allowed = true
			break
		}
	}
	if !allowed {
		return nil, fmt.Errorf("node %q is not selectable", name)
	}

	payload := struct {
		Name string `json:"name"`
	}{Name: name}
	if err := c.putJSON(ctx, "/proxies/"+url.PathEscape(available.Selector), payload); err != nil {
		return nil, err
	}

	return c.ListNodes(ctx)
}

func (c *mihomoNodeClient) getEntries(ctx context.Context) (map[string]mihomoProxyEntry, error) {
	var entries map[string]mihomoProxyEntry
	if err := c.doJSON(ctx, http.MethodGet, "/proxies", nil, &entries); err != nil {
		return nil, err
	}
	return entries, nil
}

func (c *mihomoNodeClient) putJSON(ctx context.Context, path string, payload any) error {
	return c.doJSON(ctx, http.MethodPut, path, payload, nil)
}

func (c *mihomoNodeClient) doJSON(ctx context.Context, method, path string, payload any, result any) error {
	if c == nil || c.client == nil {
		return fmt.Errorf("mihomo controller is not configured")
	}
	requestURL := c.baseURL + path
	var body io.Reader
	if payload != nil {
		encoded, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode mihomo request: %w", err)
		}
		body = strings.NewReader(string(encoded))
	}

	req, err := http.NewRequestWithContext(ctx, method, requestURL, body)
	if err != nil {
		return fmt.Errorf("create mihomo request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("mihomo controller request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("mihomo controller returned HTTP %d", resp.StatusCode)
	}
	if result == nil {
		return nil
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, maxMihomoResponseBytes))
	if err := decoder.Decode(result); err != nil {
		return fmt.Errorf("decode mihomo response: %w", err)
	}
	return nil
}

func isSelectorEntry(entry mihomoProxyEntry) bool {
	return strings.EqualFold(entry.Type, "Selector") || strings.EqualFold(entry.Type, "URLTest") || len(entry.All) > 0
}

func (entry mihomoProxyEntry) IsAvailable() bool {
	if entry.Alive != nil {
		return *entry.Alive
	}
	return !strings.EqualFold(entry.Type, "Reject")
}
