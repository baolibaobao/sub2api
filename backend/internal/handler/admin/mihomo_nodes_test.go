package admin

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMihomoNodeClientListsSelectableNodesWithoutSecrets(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/proxies" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer test-secret" {
			t.Fatalf("unexpected authorization header: %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"节点选择": map[string]any{
				"name": "节点选择",
				"type": "Selector",
				"now":  "自动选择",
				"all":  []string{"自动选择", "JP-01", "REJECT"},
			},
			"自动选择": map[string]any{
				"name": "自动选择",
				"type": "URLTest",
				"now":  "JP-01",
				"all":  []string{"JP-01"},
			},
			"JP-01": map[string]any{
				"name":  "JP-01",
				"type":  "Shadowsocks",
				"alive": true,
			},
			"REJECT": map[string]any{
				"name": "REJECT",
				"type": "Reject",
			},
		})
	}))
	defer server.Close()

	client := &mihomoNodeClient{
		client:       server.Client(),
		baseURL:      server.URL,
		secret:       "test-secret",
		selectorName: "节点选择",
		proxyID:      1,
	}

	result, err := client.ListNodes(context.Background())
	if err != nil {
		t.Fatalf("ListNodes returned error: %v", err)
	}
	if result.Selector != "节点选择" || result.Current != "自动选择" {
		t.Fatalf("unexpected selector state: %+v", result)
	}
	if len(result.Nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(result.Nodes))
	}
	if !result.Nodes[0].IsSelected || result.Nodes[0].Name != "自动选择" {
		t.Fatalf("current node was not marked: %+v", result.Nodes[0])
	}
	if result.Nodes[2].IsAvailable {
		t.Fatalf("reject entry should not be selectable: %+v", result.Nodes[2])
	}
	encoded, _ := json.Marshal(result)
	if strings.Contains(string(encoded), "test-secret") {
		t.Fatal("response leaked controller credentials")
	}
}

func TestMihomoNodeClientSelectsOnlyListedAvailableNode(t *testing.T) {
	selected := "自动选择"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"节点选择": map[string]any{
					"name": "节点选择",
					"type": "Selector",
					"now":  selected,
					"all":  []string{"自动选择", "JP-01"},
				},
				"自动选择":  map[string]any{"name": "自动选择", "type": "URLTest", "all": []string{"JP-01"}},
				"JP-01": map[string]any{"name": "JP-01", "type": "Shadowsocks", "alive": true},
			})
		case http.MethodPut:
			if !strings.HasSuffix(r.URL.Path, "/proxies/%E8%8A%82%E7%82%B9%E9%80%89%E6%8B%A9") && !strings.HasSuffix(r.URL.Path, "/proxies/节点选择") {
				t.Fatalf("unexpected select path: %s", r.URL.Path)
			}
			var payload struct {
				Name string `json:"name"`
			}
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode selection: %v", err)
			}
			selected = payload.Name
			w.WriteHeader(http.StatusNoContent)
		default:
			t.Fatalf("unexpected method: %s", r.Method)
		}
	}))
	defer server.Close()

	client := &mihomoNodeClient{
		client:       server.Client(),
		baseURL:      server.URL,
		selectorName: "节点选择",
		proxyID:      1,
	}

	result, err := client.SelectNode(context.Background(), "JP-01")
	if err != nil {
		t.Fatalf("SelectNode returned error: %v", err)
	}
	if selected != "JP-01" || result.Current != "JP-01" {
		t.Fatalf("node was not selected: selected=%q result=%+v", selected, result)
	}
	if _, err := client.SelectNode(context.Background(), "REJECT"); err == nil {
		t.Fatal("expected unavailable node selection to fail")
	}
}
