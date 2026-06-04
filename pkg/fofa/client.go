package fofa

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const defaultAPIBase = "https://fofa.info/api/v1/search/all"

// Config holds persistent credentials stored in ~/.fofa-afrog.json.
type Config struct {
	Email  string `json:"email"`
	APIKey string `json:"api_key"`
}

// ConfigPath returns the default config file path.
func ConfigPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".fofa-afrog.json"
	}
	return filepath.Join(home, ".fofa-afrog.json")
}

// LoadConfig reads credentials from the config file.
// Returns an empty Config (no error) if the file does not exist.
func LoadConfig() (Config, error) {
	var cfg Config
	data, err := os.ReadFile(ConfigPath())
	if os.IsNotExist(err) {
		return cfg, nil
	}
	if err != nil {
		return cfg, fmt.Errorf("read config: %w", err)
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config: %w", err)
	}
	return cfg, nil
}

// SaveConfig writes credentials to the config file (mode 0600).
func SaveConfig(cfg Config) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(ConfigPath(), data, 0o600)
}

// Client is a FOFA API client.
type Client struct {
	Email   string
	APIKey  string
	APIBase string
	HTTP    *http.Client
}

// NewClient creates a new FOFA client with the provided credentials.
func NewClient(email, apiKey string) *Client {
	return &Client{
		Email:   email,
		APIKey:  apiKey,
		APIBase: defaultAPIBase,
		HTTP:    &http.Client{Timeout: 30 * time.Second},
	}
}

// SearchResponse represents the FOFA API response.
type SearchResponse struct {
	Error   bool       `json:"error"`
	ErrMsg  string     `json:"errmsg"`
	Size    int        `json:"size"`
	Page    int        `json:"page"`
	Mode    string     `json:"mode"`
	Query   string     `json:"query"`
	Results [][]string `json:"results"`
}

// SearchParams holds parameters for a FOFA query.
type SearchParams struct {
	Query  string
	Fields string
	Page   int
	Size   int
	Full   bool
}

// DefaultParams returns SearchParams with sensible defaults.
func DefaultParams(query string) SearchParams {
	return SearchParams{
		Query:  query,
		Fields: "host,ip,port,title,protocol",
		Page:   1,
		Size:   100,
		Full:   false,
	}
}

// Search queries the FOFA API and returns the parsed response.
func (c *Client) Search(params SearchParams) (*SearchResponse, error) {
	if params.Fields == "" {
		params.Fields = "host,ip,port,title,protocol"
	}
	if params.Page == 0 {
		params.Page = 1
	}
	if params.Size == 0 {
		params.Size = 100
	}

	qb64 := base64.StdEncoding.EncodeToString([]byte(params.Query))

	u, err := url.Parse(c.APIBase)
	if err != nil {
		return nil, fmt.Errorf("invalid API base URL: %w", err)
	}

	q := u.Query()
	if c.Email != "" {
		q.Set("email", c.Email)
	}
	q.Set("key", c.APIKey)
	q.Set("qbase64", qb64)
	q.Set("fields", params.Fields)
	q.Set("page", fmt.Sprintf("%d", params.Page))
	q.Set("size", fmt.Sprintf("%d", params.Size))
	if params.Full {
		q.Set("full", "true")
	}
	u.RawQuery = q.Encode()

	resp, err := c.HTTP.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	var result SearchResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	if result.Error {
		return nil, fmt.Errorf("FOFA API error: %s", result.ErrMsg)
	}

	return &result, nil
}

// FieldNames parses a comma-separated fields string into a slice.
func FieldNames(fields string) []string {
	return strings.Split(fields, ",")
}
