package api

import (
	"context"
	"encoding/json"
	"io"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/pyzanode/controller/internal/auth"
	"github.com/pyzanode/controller/internal/cloudflare"
	"github.com/pyzanode/controller/internal/hub"
	"github.com/pyzanode/controller/internal/logstream"
	"github.com/pyzanode/controller/internal/store"
	"github.com/pyzanode/shared/debuglog"
	"github.com/pyzanode/shared/types"
)

type API struct {
	store     *store.Store
	auth      *auth.Auth
	hub       *hub.Hub
	logStream *logstream.LogStream
	scalerMu  sync.Mutex // prevents overlapping scaler runs and double-creates
}

type ctxKey string

const principalCtxKey ctxKey = "principal"

func principalFromRequest(r *http.Request) *auth.Principal {
	v := r.Context().Value(principalCtxKey)
	p, _ := v.(*auth.Principal)
	return p
}

func withPrincipal(r *http.Request, p *auth.Principal) *http.Request {
	ctx := context.WithValue(r.Context(), principalCtxKey, p)
	return r.WithContext(ctx)
}

func New(store *store.Store, auth *auth.Auth) *API {
	return &API{store: store, auth: auth}
}

// throttle SPA root logging: same client hitting GET / or /index.html repeatedly only logs once per window
const spaLogThrottleWindow = 10 * time.Second

var (
	spaLogMu     sync.Mutex
	spaLogLast   = map[string]time.Time{}
	spaLogCount  = map[string]int{}
)

func (a *API) logMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		path := r.URL.Path
		throttle := (r.Method == http.MethodGet && (path == "/" || path == "/index.html" || path == "/dashboard" || path == "/dashboard/"))
		skipLog := false
		if throttle {
			spaLogMu.Lock()
			key := r.RemoteAddr
			last := spaLogLast[key]
			n := spaLogCount[key]
			now := time.Now()
			if now.Sub(last) < spaLogThrottleWindow {
				spaLogCount[key] = n + 1
				spaLogMu.Unlock()
				skipLog = true
			} else {
				if n > 0 {
					// Treat high-frequency SPA root hits as debug-level traffic.
					debuglog.Printf("[api] GET %s from %s (repeated %d times in last %.0fs)", path, key, n, spaLogThrottleWindow.Seconds())
				}
				spaLogLast[key] = now
				spaLogCount[key] = 0
				spaLogMu.Unlock()
			}
		}
		// Per-request API logging is considered debug; only emit when debug logging is enabled.
		if !skipLog {
			debuglog.Printf("[api] %s %s from %s", r.Method, path, r.RemoteAddr)
		}
		next.ServeHTTP(w, r)
		dur := time.Since(start)
		if !skipLog {
			debuglog.Printf("[api] %s %s done in %v", r.Method, path, dur)
		}
	})
}

func (a *API) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		w.Header().Set("Access-Control-Max-Age", "86400")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// handleCORSOptions responds to OPTIONS (preflight) with CORS headers. Registered explicitly so preflight always succeeds.
func (a *API) handleCORSOptions(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
	w.Header().Set("Access-Control-Max-Age", "86400")
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/api/auth/login") || strings.HasPrefix(r.URL.Path, "/api/auth/setup/") || r.URL.Path == "/api/init" || r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		if a.auth.NeedsSetup() {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "setup required"})
			return
		}
		token := r.Header.Get("Authorization")
		if token != "" && strings.HasPrefix(token, "Bearer ") {
			token = strings.TrimPrefix(token, "Bearer ")
		}
		if token == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		p, err := a.auth.ValidateJWT(token)
		if err == nil {
			if !p.IsAdmin() {
				if !a.checkPermission(w, r, p) {
					return
				}
			}
			next.ServeHTTP(w, withPrincipal(r, p))
			return
		}

		if a.auth.ValidateAgentToken(token) {
			legacy := &auth.Principal{
				UserID:      "legacy-agent",
				Username:    "legacy-agent",
				Role:        "admin",
				Permissions: map[string]bool{"*": true},
				NetworkIDs:  map[string]bool{},
			}
			next.ServeHTTP(w, withPrincipal(r, legacy))
			return
		}

		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	})
}


func (a *API) checkPermission(w http.ResponseWriter, r *http.Request, p *auth.Principal) bool {
	path := r.URL.Path
	method := r.Method
	req := ""
	switch {
	case strings.HasPrefix(path, "/api/auth/users"):
		req = "users.manage"
	case strings.HasPrefix(path, "/api/nodes"):
		if method == http.MethodGet {
			req = "nodes.view"
		} else {
			req = "nodes.manage"
		}
	case strings.HasPrefix(path, "/api/networks"):
		if method == http.MethodGet {
			req = "networks.view"
		} else {
			req = "networks.manage"
		}
	case strings.HasPrefix(path, "/api/server-groups"):
		if method == http.MethodGet {
			req = "server_groups.view"
		} else {
			req = "server_groups.manage"
		}
	case strings.HasPrefix(path, "/api/proxy-groups"):
		if method == http.MethodGet {
			req = "proxy_groups.view"
		} else {
			req = "proxy_groups.manage"
		}
	case strings.HasPrefix(path, "/api/servers"):
		if strings.HasSuffix(path, "/start") || strings.HasSuffix(path, "/stop") || strings.HasSuffix(path, "/restart") {
			req = "servers.control"
		} else if strings.HasSuffix(path, "/command") {
			req = "servers.command"
		} else if method == http.MethodGet {
			req = "servers.view"
		} else {
			req = "servers.manage"
		}
	case strings.HasPrefix(path, "/api/presets"):
		if method == http.MethodGet {
			req = "presets.view"
		} else {
			req = "presets.manage"
		}
	case strings.HasPrefix(path, "/api/settings"):
		req = "settings.manage"
	case strings.HasPrefix(path, "/api/analytics"):
		if strings.HasSuffix(path, "/cleanup") {
			req = "settings.manage"
		} else {
			req = "analytics.view"
		}
	}
	if req != "" && !p.Can(req) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return false
	}
	return true
}

func (a *API) Router(agentWSPath string, h *hub.Hub, webDir string, embedWeb *fs.FS) http.Handler {
	a.hub = h
	a.logStream = logstream.New(500)
	go a.runScalerLoop()
	// Kick off Cloudflare SRV sync for all networks that have it configured.
	go cloudflare.SyncSRVForAllNetworks(a.store)
	r := mux.NewRouter()
	r.Use(a.logMiddleware, a.corsMiddleware)
	// Explicit OPTIONS handler so browser preflight always gets CORS headers (some clients need this)
	r.Methods("OPTIONS").PathPrefix("/").HandlerFunc(a.handleCORSOptions)
	r.HandleFunc("/health", a.Health).Methods("GET")
	r.HandleFunc("/api/init", a.Init).Methods("GET")
	if h != nil && agentWSPath != "" {
		r.HandleFunc(agentWSPath, a.HandleAgentWS(h)).Methods("GET")
	}
	r.HandleFunc("/ws/logs", a.HandleLogsWS()).Methods("GET")

	api := r.PathPrefix("/api").Subrouter()
	api.Use(a.authMiddleware)
	api.HandleFunc("/auth/login", a.AuthLogin).Methods("POST")
	api.HandleFunc("/auth/setup/status", a.AuthSetupStatus).Methods("GET")
	api.HandleFunc("/auth/setup/complete", a.AuthSetupComplete).Methods("POST")
	api.HandleFunc("/auth/me", a.AuthMe).Methods("GET")
	api.HandleFunc("/auth/users", a.AuthUsersList).Methods("GET")
	api.HandleFunc("/auth/users", a.AuthUsersUpsert).Methods("POST")
	api.HandleFunc("/auth/users/{username}", a.AuthUsersDelete).Methods("DELETE")

	// Nodes
	api.HandleFunc("/nodes", a.NodesList).Methods("GET")
	api.HandleFunc("/nodes/{id}/debug", a.NodeSetDebug).Methods("POST")
	api.HandleFunc("/nodes/{id}", a.NodeGet).Methods("GET")
	api.HandleFunc("/nodes/{id}", a.NodeUpdate).Methods("PUT")
	api.HandleFunc("/nodes/{id}", a.NodeDelete).Methods("DELETE")

	// Servers (specific path before {id} so scale-group is not captured as id)
	api.HandleFunc("/servers", a.ServersList).Methods("GET")
	api.HandleFunc("/servers", a.ServerCreate).Methods("POST")
	api.HandleFunc("/servers/scale-group", a.ServersScaleGroup).Methods("POST")
	api.HandleFunc("/servers/{id}", a.ServerGet).Methods("GET")
	api.HandleFunc("/servers/{id}/start", a.ServerStart).Methods("POST")
	api.HandleFunc("/servers/{id}/stop", a.ServerStop).Methods("POST")
	api.HandleFunc("/servers/{id}/restart", a.ServerRestart).Methods("POST")
	api.HandleFunc("/servers/{id}/command", a.ServerCommand).Methods("POST")
	api.HandleFunc("/servers/{id}/metrics-plugin", a.ServerPluginMetrics).Methods("POST")
	api.HandleFunc("/servers/{id}/logs", a.ServerLogs).Methods("GET")
	api.HandleFunc("/servers/{id}", a.ServerDelete).Methods("DELETE")
	api.HandleFunc("/servers/{id}", a.ServerUpdate).Methods("PUT")

	// Networks (Minecraft network ecosystems)
	api.HandleFunc("/networks", a.NetworksList).Methods("GET")
	api.HandleFunc("/networks", a.NetworkCreate).Methods("POST")
	api.HandleFunc("/networks/{id}", a.NetworkGet).Methods("GET")
	api.HandleFunc("/networks/{id}", a.NetworkUpdate).Methods("PUT")
	api.HandleFunc("/networks/{id}", a.NetworkDelete).Methods("DELETE")
	// Server Groups (auto-scaled backends)
	api.HandleFunc("/server-groups", a.ServerGroupsList).Methods("GET")
	api.HandleFunc("/server-groups", a.ServerGroupCreate).Methods("POST")
	api.HandleFunc("/server-groups/{id}", a.ServerGroupGet).Methods("GET")
	api.HandleFunc("/server-groups/{id}", a.ServerGroupUpdate).Methods("PUT")
	api.HandleFunc("/server-groups/{id}", a.ServerGroupDelete).Methods("DELETE")
	// Proxy Groups (load-balanced proxies)
	api.HandleFunc("/proxy-groups", a.ProxyGroupsList).Methods("GET")
	api.HandleFunc("/proxy-groups", a.ProxyGroupCreate).Methods("POST")
	api.HandleFunc("/proxy-groups/{id}", a.ProxyGroupGet).Methods("GET")
	api.HandleFunc("/proxy-groups/{id}", a.ProxyGroupUpdate).Methods("PUT")
	api.HandleFunc("/proxy-groups/{id}", a.ProxyGroupDelete).Methods("DELETE")

	// Settings
	api.HandleFunc("/settings/auto-port-forward-upnp", a.SettingsGetAutoPortForwardUPnP).Methods("GET")
	api.HandleFunc("/settings/auto-port-forward-upnp", a.SettingsPutAutoPortForwardUPnP).Methods("PUT")
	api.HandleFunc("/settings/debug-logging", a.SettingsGetDebugLogging).Methods("GET")
	api.HandleFunc("/settings/debug-logging", a.SettingsPutDebugLogging).Methods("PUT")
	api.HandleFunc("/settings/api-key", a.SettingsGetAPIKey).Methods("GET")
	api.HandleFunc("/settings/notifications", a.SettingsGetNotifications).Methods("GET")
	api.HandleFunc("/settings/notifications", a.SettingsPutNotifications).Methods("PUT")

	// Analytics
	api.HandleFunc("/analytics/summary", a.AnalyticsSummary).Methods("GET")
	api.HandleFunc("/analytics/events", a.AnalyticsEvents).Methods("GET")
	api.HandleFunc("/analytics/players", a.AnalyticsPlayers).Methods("GET")
	api.HandleFunc("/analytics/cleanup", a.AnalyticsCleanup).Methods("POST")

	// Presets
	api.HandleFunc("/presets", a.PresetsList).Methods("GET")
	api.HandleFunc("/presets", a.PresetCreate).Methods("POST")
	api.HandleFunc("/presets/build-package", a.BuildPackage).Methods("POST")
	api.HandleFunc("/presets/build-image", a.BuildImage).Methods("POST")
	api.HandleFunc("/presets/{id}", a.PresetGet).Methods("GET")
	api.HandleFunc("/presets/{id}/package", a.PresetPackage).Methods("GET")
	api.HandleFunc("/presets/{id}/package", a.PresetPackageUpload).Methods("POST")
	api.HandleFunc("/presets/{id}", a.PresetUpdate).Methods("PUT")
	api.HandleFunc("/presets/{id}", a.PresetDelete).Methods("DELETE")

	// Dashboard at /dashboard/ (one redirect / -> /dashboard/ avoids redirect loop at root).
	const dashboardPrefix = "/dashboard"
	if webDir != "" {
		if info, err := os.Stat(webDir); err != nil || !info.IsDir() {
			log.Printf("web dir %q missing or not a directory; dashboard will not be served", webDir)
		} else {
			r.HandleFunc("/", a.redirectToDashboard).Methods("GET")
			r.HandleFunc("/index.html", a.redirectToDashboard).Methods("GET")
			r.PathPrefix(dashboardPrefix + "/").Handler(spaFileServerAt(dashboardPrefix, webDir))
			r.HandleFunc(dashboardPrefix, a.redirectToDashboard).Methods("GET")
		}
	} else if embedWeb != nil {
		r.HandleFunc("/", a.redirectToDashboard).Methods("GET")
		r.HandleFunc("/index.html", a.redirectToDashboard).Methods("GET")
		r.PathPrefix(dashboardPrefix + "/").Handler(spaFileServerEmbedAt(dashboardPrefix, *embedWeb))
		r.HandleFunc(dashboardPrefix, a.redirectToDashboard).Methods("GET")
	} else {
		r.HandleFunc("/", a.serveDashboardInfo).Methods("GET")
		r.HandleFunc("/index.html", a.serveDashboardInfo).Methods("GET")
	}

	return r
}

// redirectToDashboard sends a single redirect to /dashboard/ so the SPA loads there (avoids redirect loop at /).
func (a *API) redirectToDashboard(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/dashboard/", http.StatusFound)
}

// spaFileServerAt serves the SPA from dir under the given path prefix (e.g. /dashboard). Strips prefix from r.URL.Path.
// Serves index.html directly for directory-like paths to avoid Go FileServer's 301 redirect to "./".
func spaFileServerAt(prefix, dir string) http.Handler {
	fileFS := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, prefix)
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = path.Clean(p)
		if p == "." || p == "/" {
			serveDirIndex(w, dir)
			return
		}
		full := filepath.Join(dir, strings.TrimPrefix(p, "/"))
		if fi, err := os.Stat(full); err != nil || fi.IsDir() {
			serveDirIndex(w, dir)
			return
		}
		r.URL.Path = p
		fileFS.ServeHTTP(w, r)
	})
}

// serveDirIndex writes index.html from dir. Used so we never pass "/index.html"
// to FileServer (which would 301 redirect to "./" and cause a loop).
func serveDirIndex(w http.ResponseWriter, dir string) {
	data, err := os.ReadFile(filepath.Join(dir, "index.html"))
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// spaFileServerEmbedAt serves the SPA from embedded fs under the given path prefix.
// Serves index.html directly for directory-like paths to avoid Go FileServer's 301 redirect to "./".
func spaFileServerEmbedAt(prefix string, efs fs.FS) http.Handler {
	fileFS := http.FileServer(http.FS(efs))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		p := strings.TrimPrefix(r.URL.Path, prefix)
		if p == "" {
			p = "/"
		}
		if !strings.HasPrefix(p, "/") {
			p = "/" + p
		}
		p = path.Clean(p)
		name := strings.TrimPrefix(p, "/")
		if name == "" || name == "." {
			serveEmbedIndex(w, efs)
			return
		}
		if _, err := fs.Stat(efs, name); err != nil {
			serveEmbedIndex(w, efs)
			return
		}
		r.URL.Path = "/" + name
		fileFS.ServeHTTP(w, r)
	})
}

// serveEmbedIndex writes index.html from the embedded FS. Used so we never pass
// "/index.html" to FileServer (which would 301 redirect to "./" and cause a loop).
func serveEmbedIndex(w http.ResponseWriter, efs fs.FS) {
	data, err := fs.ReadFile(efs, "index.html")
	if err != nil {
		http.NotFound(w, nil)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// spaFileServer serves static files from dir and falls back to index.html for SPA client-side routing.
func spaFileServer(dir string) http.Handler {
	fileFS := http.FileServer(http.Dir(dir))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		p := path.Clean(r.URL.Path)
		if p == "." || p == "/" {
			r.URL.Path = "/index.html"
			w.Header().Set("Cache-Control", "no-store")
			fileFS.ServeHTTP(w, r)
			return
		}
		full := filepath.Join(dir, strings.TrimPrefix(p, "/"))
		fi, err := os.Stat(full)
		if err != nil || fi.IsDir() {
			r.URL.Path = "/index.html"
			w.Header().Set("Cache-Control", "no-store")
			fileFS.ServeHTTP(w, r)
			return
		}
		fileFS.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	if rc := http.NewResponseController(w); rc != nil {
		_ = rc.SetWriteDeadline(time.Now().Add(5 * time.Second))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
}

func (a *API) Health(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// serveDashboardInfo is the root handler when the controller does not serve the dashboard (default).
// It tells the user to run the web UI on another port.
func (a *API) serveDashboardInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	const body = `<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PyzaNode controller</title></head>
<body style="font-family:system-ui,sans-serif;max-width:36em;margin:3em auto;padding:0 1em;color:#333;">
<h1>PyzaNode controller</h1>
<p>API is running on this port. The dashboard runs on a <strong>separate port</strong>.</p>
<p>Open the web UI:</p>
<ul>
  <li><strong>Dev:</strong> <code>cd web && npm run dev</code>, then open <a href="http://localhost:5173">http://localhost:5173</a></li>
  <li><strong>Prod:</strong> serve the <code>web/dist</code> folder (e.g. <code>npx serve -s web/dist -l 3000</code>) and open that URL</li>
</ul>
<p>The dashboard will connect to this controller at <code id="api"></code>.</p>
<script>document.getElementById("api").textContent = window.location.origin;</script>
</body></html>`
	_, _ = w.Write([]byte(body))
}

func (a *API) Init(w http.ResponseWriter, r *http.Request) {
	// After setup, require auth so the agent token is not exposed to unauthenticated callers.
	if !a.auth.NeedsSetup() {
		tok := r.Header.Get("Authorization")
		if tok != "" && strings.HasPrefix(tok, "Bearer ") {
			tok = strings.TrimPrefix(tok, "Bearer ")
		}
		if tok == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if _, err := a.auth.ValidateJWT(tok); err != nil && !a.auth.ValidateAgentToken(tok) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
	}
	token, err := a.auth.EnsureSecrets()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"token":     token,
		"message":   "PyzaNode controller ready. Use this token to connect agents. Set the admin password in the dashboard before signing in.",
		"agent_cmd": "pyzanode-agent connect <controller-url> " + token,
	})
}

func (a *API) AuthLogin(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	token, user, err := a.auth.Login(strings.TrimSpace(body.Username), body.Password)
	if err != nil {
		debuglog.Printf("[auth] login failed: user=%q err=%v", body.Username, err)
		if strings.Contains(err.Error(), "setup required") {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "setup required"})
			return
		}
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid username or password"})
		return
	}
	debuglog.Printf("[auth] login ok: user=%s", user.Username)
	writeJSON(w, http.StatusOK, map[string]interface{}{"token": token, "user": user})
}

func (a *API) AuthSetupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.auth.SetupStatus())
}

func (a *API) AuthSetupComplete(w http.ResponseWriter, r *http.Request) {
	if !a.auth.NeedsSetup() {
		debuglog.Printf("[auth] setup complete called but already configured")
		writeJSON(w, http.StatusOK, map[string]string{"status": "already configured"})
		return
	}
	var body struct {
		AdminPassword string `json:"admin_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		debuglog.Printf("[auth] setup complete invalid body: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := a.auth.CompleteInitialSetup(body.AdminPassword); err != nil {
		debuglog.Printf("[auth] setup complete failed: %v", err)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	debuglog.Printf("[auth] setup complete ok")
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) AuthMe(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	if p == nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	perms := make([]string, 0, len(p.Permissions))
	for k := range p.Permissions {
		perms = append(perms, k)
	}
	networks := make([]string, 0, len(p.NetworkIDs))
	for k := range p.NetworkIDs {
		networks = append(networks, k)
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id":          p.UserID,
		"username":    p.Username,
		"role":        p.Role,
		"permissions": perms,
		"network_ids": networks,
	})
}

func (a *API) AuthUsersList(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.auth.ListUsers())
}

func (a *API) AuthUsersUpsert(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Username    string   `json:"username"`
		Password    string   `json:"password"`
		Email       string   `json:"email"`
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
		NetworkIDs  []string `json:"network_ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	user, err := a.auth.UpsertUser(body.Username, body.Password, body.Role, body.Email, body.Permissions, body.NetworkIDs)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (a *API) AuthUsersDelete(w http.ResponseWriter, r *http.Request) {
	username := mux.Vars(r)["username"]
	if err := a.auth.DeleteUser(username); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) SettingsGetAutoPortForwardUPnP(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": a.store.GetSettings().AutoPortForwardUPnP})
}

func (a *API) SettingsPutAutoPortForwardUPnP(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := a.store.SetAutoPortForwardUPnP(body.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": a.store.GetSettings().AutoPortForwardUPnP})
}

func (a *API) SettingsGetDebugLogging(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": a.store.GetSettings().DebugLogging})
}

func (a *API) SettingsPutDebugLogging(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := a.store.SetDebugLogging(body.Enabled); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	debuglog.Enabled = body.Enabled
	writeJSON(w, http.StatusOK, map[string]bool{"enabled": a.store.GetSettings().DebugLogging})
}

func (a *API) SettingsGetAPIKey(w http.ResponseWriter, r *http.Request) {
	p := principalFromRequest(r)
	if p == nil || !p.IsAdmin() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "admin only"})
		return
	}
	key := a.auth.GetAPIToken()
	writeJSON(w, http.StatusOK, map[string]string{"api_key": key})
}

// SettingsGetNotifications returns notification + ntfy settings.
// Password is never returned; ntfy_has_password is true when a password is set.
func (a *API) SettingsGetNotifications(w http.ResponseWriter, r *http.Request) {
	st := a.store.GetSettings()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"notify_on_crash":          st.NotifyOnCrash,
		"notify_on_node_disconnect": st.NotifyOnNodeDisconnect,
		"ntfy_url":                 st.NtfyURL,
		"ntfy_topic":               st.NtfyTopic,
		"ntfy_token":               st.NtfyToken,
		"ntfy_username":            st.NtfyUsername,
		"ntfy_has_password":        st.NtfyPassword != "",
	})
}

// SettingsPutNotifications updates notification + ntfy settings.
// NtfyPassword: if empty, existing password is kept; if set, it is updated.
func (a *API) SettingsPutNotifications(w http.ResponseWriter, r *http.Request) {
	var body struct {
		NotifyOnCrash          bool   `json:"notify_on_crash"`
		NotifyOnNodeDisconnect bool   `json:"notify_on_node_disconnect"`
		NtfyURL                string `json:"ntfy_url"`
		NtfyTopic              string `json:"ntfy_topic"`
		NtfyToken              string `json:"ntfy_token"`
		NtfyUsername           string `json:"ntfy_username"`
		NtfyPassword           string `json:"ntfy_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if err := a.store.UpdateNotificationSettings(body.NotifyOnCrash, body.NotifyOnNodeDisconnect, body.NtfyURL, body.NtfyTopic, body.NtfyToken, body.NtfyUsername, body.NtfyPassword); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (a *API) AnalyticsSummary(w http.ResponseWriter, r *http.Request) {
	networkID := strings.TrimSpace(r.URL.Query().Get("network_id"))
	if networkID != "" && !a.requireNetworkAccess(w, r, networkID) {
		return
	}
	writeJSON(w, http.StatusOK, a.store.AnalyticsSummary(networkID))
}

func (a *API) AnalyticsEvents(w http.ResponseWriter, r *http.Request) {
	networkID := strings.TrimSpace(r.URL.Query().Get("network_id"))
	if networkID != "" && !a.requireNetworkAccess(w, r, networkID) {
		return
	}
	limit := 200
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 2000 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, a.store.AnalyticsEvents(limit, networkID))
}

func (a *API) AnalyticsPlayers(w http.ResponseWriter, r *http.Request) {
	networkID := strings.TrimSpace(r.URL.Query().Get("network_id"))
	if networkID != "" && !a.requireNetworkAccess(w, r, networkID) {
		return
	}
	limit := 500
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 5000 {
			limit = n
		}
	}
	writeJSON(w, http.StatusOK, a.store.AnalyticsPlayers(networkID, limit))
}

func (a *API) AnalyticsCleanup(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, a.store.CleanupAnalytics())
}

const nodeStaleThreshold = 2 * time.Minute

func (a *API) canAccessNetwork(r *http.Request, networkID string) bool {
	p := principalFromRequest(r)
	if p == nil {
		return false
	}
	return p.CanAccessNetwork(networkID)
}

func (a *API) requireNetworkAccess(w http.ResponseWriter, r *http.Request, networkID string) bool {
	if a.canAccessNetwork(r, networkID) {
		return true
	}
	writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
	return false
}

func (a *API) serverNetworkID(sv *types.Server) string {
	if sv == nil {
		return ""
	}
	if sv.NetworkID != "" {
		return sv.NetworkID
	}
	if sv.ServerGroupID != "" {
		if g := a.store.ServerGroupByID(sv.ServerGroupID); g != nil {
			return g.NetworkID
		}
	}
	if sv.ProxyGroupID != "" {
		if g := a.store.ProxyGroupByID(sv.ProxyGroupID); g != nil {
			return g.NetworkID
		}
	}
	return ""
}

// nodeHealth returns health for display; if LastHeartbeat is too old, treat as offline.
func nodeHealth(n *types.Node) string {
	if n == nil {
		return "unknown"
	}
	if n.Health == "offline" {
		return "offline"
	}
	if time.Since(n.LastHeartbeat) > nodeStaleThreshold {
		return "offline"
	}
	return n.Health
}

// nodeIsOffline returns true if the node is considered offline (no recent heartbeat or health offline).
func (a *API) nodeIsOffline(nodeID string) bool {
	return nodeHealth(a.store.NodeByID(nodeID)) == "offline"
}

func (a *API) NodesList(w http.ResponseWriter, r *http.Request) {
	list := a.store.NodesList()
	// Expose effective health (offline if no recent heartbeat)
	out := make([]map[string]interface{}, 0, len(list))
	for _, n := range list {
		usePub := n.UsePublicHostname == nil || *n.UsePublicHostname
		m := map[string]interface{}{
			"id": n.ID, "hostname": n.Hostname, "address": n.Address, "public_hostname": n.PublicHostname, "use_public_hostname": usePub, "os": n.OS,
			"cpu_usage": n.CPUUsage, "ram_usage": n.RAMUsage, "ram_total": n.RAMTotal,
			"disk_usage": n.DiskUsage, "disk_total": n.DiskTotal,
			"network_rx": n.NetworkRx, "network_tx": n.NetworkTx,
			"cpu_usage_servers": n.CPUUsageServers, "ram_usage_servers": n.RAMUsageServers,
			"running_count": n.RunningCount, "last_heartbeat": n.LastHeartbeat,
			"debug_enabled": n.DebugEnabled,
			"tags": n.Tags, "created_at": n.CreatedAt,
		}
		if n.Alert != "" {
			m["alert"] = n.Alert
		}
		m["health"] = nodeHealth(n)
		out = append(out, m)
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *API) NodeGet(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	n := a.store.NodeByID(id)
	if n == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	usePub := n.UsePublicHostname == nil || *n.UsePublicHostname
	out := map[string]interface{}{
		"id": n.ID, "hostname": n.Hostname, "address": n.Address, "public_hostname": n.PublicHostname, "use_public_hostname": usePub, "os": n.OS,
		"cpu_usage": n.CPUUsage, "ram_usage": n.RAMUsage, "ram_total": n.RAMTotal,
		"disk_usage": n.DiskUsage, "disk_total": n.DiskTotal,
		"network_rx": n.NetworkRx, "network_tx": n.NetworkTx,
		"cpu_usage_servers": n.CPUUsageServers, "ram_usage_servers": n.RAMUsageServers,
		"running_count": n.RunningCount, "last_heartbeat": n.LastHeartbeat,
		"debug_enabled": n.DebugEnabled,
		"tags": n.Tags, "created_at": n.CreatedAt,
	}
	if n.Alert != "" {
		out["alert"] = n.Alert
	}
	out["health"] = nodeHealth(n)
	writeJSON(w, http.StatusOK, out)
}

// NodeSetDebug sends a set_debug command to the agent so debug logging can be toggled without restarting the node.
func (a *API) NodeSetDebug(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	n := a.store.NodeByID(id)
	if n == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if a.hub == nil || !a.hub.SendCommand(id, "set_debug", map[string]bool{"enabled": body.Enabled}) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "node not connected"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"debug": body.Enabled})
}

// NodeUpdate updates editable node metadata (public_hostname, address, use_public_hostname).
func (a *API) NodeUpdate(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	n := a.store.NodeByID(id)
	if n == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	var body struct {
		PublicHostname   *string `json:"public_hostname"`
		Address          *string `json:"address"` // Local/LAN IP (e.g. 10.0.0.110) for proxies on same network
		UsePublicHostname *bool  `json:"use_public_hostname"` // when false, proxies use address/hostname for this node's backends
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.PublicHostname != nil {
		a.store.NodeSetPublicHostname(id, *body.PublicHostname)
	}
	if body.Address != nil {
		a.store.NodeSetAddress(id, strings.TrimSpace(*body.Address))
	}
	if body.UsePublicHostname != nil {
		a.store.NodeSetUsePublicHostname(id, *body.UsePublicHostname)
	}
	// Return updated node
	n = a.store.NodeByID(id)
	if n == nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "node disappeared"})
		return
	}
	usePub := n.UsePublicHostname == nil || *n.UsePublicHostname
	out := map[string]interface{}{
		"id": n.ID, "hostname": n.Hostname, "address": n.Address, "public_hostname": n.PublicHostname, "use_public_hostname": usePub, "os": n.OS,
		"cpu_usage": n.CPUUsage, "ram_usage": n.RAMUsage, "ram_total": n.RAMTotal,
		"disk_usage": n.DiskUsage, "disk_total": n.DiskTotal,
		"network_rx": n.NetworkRx, "network_tx": n.NetworkTx,
		"cpu_usage_servers": n.CPUUsageServers, "ram_usage_servers": n.RAMUsageServers,
		"running_count": n.RunningCount, "last_heartbeat": n.LastHeartbeat,
		"tags": n.Tags, "created_at": n.CreatedAt,
	}
	if n.Alert != "" {
		out["alert"] = n.Alert
	}
	out["health"] = nodeHealth(n)
	writeJSON(w, http.StatusOK, out)
}

func (a *API) NodeDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if a.store.NodeByID(id) == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "node not found"})
		return
	}
	a.store.NodeDelete(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) ServersList(w http.ResponseWriter, r *http.Request) {
	var list []*types.Server
	if serverGroupID := r.URL.Query().Get("server_group_id"); serverGroupID != "" {
		if g := a.store.ServerGroupByID(serverGroupID); g != nil && !a.canAccessNetwork(r, g.NetworkID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		list = a.store.ServersByServerGroup(serverGroupID)
	} else if proxyGroupID := r.URL.Query().Get("proxy_group_id"); proxyGroupID != "" {
		if g := a.store.ProxyGroupByID(proxyGroupID); g != nil && !a.canAccessNetwork(r, g.NetworkID) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
			return
		}
		list = a.store.ServersByProxyGroup(proxyGroupID)
	} else if networkID := r.URL.Query().Get("network_id"); networkID != "" {
		if !a.requireNetworkAccess(w, r, networkID) {
			return
		}
		list = a.store.ServersByNetwork(networkID)
	} else {
		list = a.store.ServersList()
	}
	p := principalFromRequest(r)
	if p != nil && !p.IsAdmin() {
		filtered := make([]*types.Server, 0, len(list))
		for _, sv := range list {
			if p.CanAccessNetwork(a.serverNetworkID(sv)) {
				filtered = append(filtered, sv)
			}
		}
		list = filtered
	}
	if group := r.URL.Query().Get("group"); group != "" {
		filtered := list[:0]
		for _, sv := range list {
			if sv.Group == group {
				filtered = append(filtered, sv)
			}
		}
		list = filtered
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) ServerGet(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sv := a.store.ServerByID(id)
	if sv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, a.serverNetworkID(sv)) {
		return
	}
	writeJSON(w, http.StatusOK, sv)
}

func (a *API) ServerCreate(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name          string `json:"name"`
		ShortCode     string `json:"short_code"`
		PresetID      string `json:"preset_id"`
		NodeID        string `json:"node_id"`
		Port          int    `json:"port"`
		Group         string `json:"group"`
		NetworkID     string `json:"network_id"`
		ServerGroupID string `json:"server_group_id"`
		ProxyGroupID  string `json:"proxy_group_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.Name == "" || body.PresetID == "" || body.NodeID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name, preset_id, node_id required"})
		return
	}
	targetNetworkID := body.NetworkID
	if body.ServerGroupID != "" {
		if g := a.store.ServerGroupByID(body.ServerGroupID); g != nil {
			targetNetworkID = g.NetworkID
		}
	}
	if body.ProxyGroupID != "" {
		if g := a.store.ProxyGroupByID(body.ProxyGroupID); g != nil {
			targetNetworkID = g.NetworkID
		}
	}
	if targetNetworkID != "" && !a.requireNetworkAccess(w, r, targetNetworkID) {
		return
	}
	sv, err := a.store.ServerCreate(body.Name, body.PresetID, body.NodeID, body.Port, body.Group, body.NetworkID, body.ServerGroupID, body.ProxyGroupID, body.ShortCode)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// Auto-start only if the node is online; otherwise leave server stopped
	if !a.nodeIsOffline(sv.NodeID) && a.hub != nil {
		preset := a.store.PresetByID(body.PresetID)
		if preset != nil {
			a.store.ServerSetStatus(sv.ID, "starting")
			payload := map[string]interface{}{"server_id": sv.ID, "preset": preset, "port": sv.Port}
			if a.store.GetSettings().AutoPortForwardUPnP {
				payload["port_forward_upnp"] = true
			}
			a.hub.SendCommand(sv.NodeID, "start_server", payload)
		}
	}
	if body.ProxyGroupID != "" {
		go cloudflare.SyncSRV(a.store, body.ProxyGroupID)
	}
	a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
		Type:      "server_created",
		NetworkID: a.serverNetworkID(sv),
		ServerID:  sv.ID,
		Server:    sv.Name,
		NodeID:    sv.NodeID,
		Message:   "Server created",
	})
	// Return server from store so response has updated status ("starting")
	if out := a.store.ServerByID(sv.ID); out != nil {
		sv = out
	}
	writeJSON(w, http.StatusCreated, sv)
}

func (a *API) ServerStart(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sv := a.store.ServerByID(id)
	if sv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, a.serverNetworkID(sv)) {
		return
	}
	if a.nodeIsOffline(sv.NodeID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Node is offline. Start the agent on that node first."})
		return
	}
	a.store.ServerSetStatus(id, "starting")
	if a.hub != nil {
		preset := a.store.PresetByID(sv.PresetID)
		if preset != nil {
			payload := map[string]interface{}{"server_id": id, "preset": preset, "port": sv.Port}
			if a.store.GetSettings().AutoPortForwardUPnP {
				payload["port_forward_upnp"] = true
			}
			a.hub.SendCommand(sv.NodeID, "start_server", payload)
		}
	}
	a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
		Type:      "server_started",
		NetworkID: a.serverNetworkID(sv),
		ServerID:  sv.ID,
		Server:    sv.Name,
		NodeID:    sv.NodeID,
		Message:   "Server start requested",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "starting"})
}

func (a *API) ServerStop(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sv := a.store.ServerByID(id)
	if sv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, a.serverNetworkID(sv)) {
		return
	}
	a.store.ServerSetStatus(id, "stopping")
	if a.hub != nil {
		a.hub.SendCommand(sv.NodeID, "stop_server", map[string]string{"server_id": id})
	}
	// If this server is in a group that has another running/starting, remove it from the list
	// so temp servers don’t pile up when you click Stop.
	if sv.Group != "" {
		groupServers := a.store.ServersByGroup(sv.Group)
		otherRunning := 0
		for _, s := range groupServers {
			if s.ID != id && (s.Status == "running" || s.Status == "starting") {
				otherRunning++
			}
		}
		if otherRunning >= 1 {
			a.store.ServerDelete(id)
		}
	}
	a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
		Type:      "server_stopped",
		NetworkID: a.serverNetworkID(sv),
		ServerID:  sv.ID,
		Server:    sv.Name,
		NodeID:    sv.NodeID,
		Message:   "Server stop requested",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "stopping"})
}

func (a *API) ServerRestart(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sv := a.store.ServerByID(id)
	if sv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, a.serverNetworkID(sv)) {
		return
	}
	if a.nodeIsOffline(sv.NodeID) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Node is offline. Start the agent on that node first."})
		return
	}
	a.store.ServerSetStatus(id, "stopping")
	if a.hub != nil {
		preset := a.store.PresetByID(sv.PresetID)
		if preset != nil {
			payload := map[string]interface{}{"server_id": id, "preset": preset, "port": sv.Port}
			if a.store.GetSettings().AutoPortForwardUPnP {
				payload["port_forward_upnp"] = true
			}
			a.hub.SendCommand(sv.NodeID, "restart_server", payload)
		}
	}
	a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
		Type:      "server_started",
		NetworkID: a.serverNetworkID(sv),
		ServerID:  sv.ID,
		Server:    sv.Name,
		NodeID:    sv.NodeID,
		Message:   "Server restart requested",
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "restarting"})
}

func (a *API) ServerCommand(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sv := a.store.ServerByID(id)
	if sv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, a.serverNetworkID(sv)) {
		return
	}
	var body struct {
		Command string `json:"command"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Command == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "body must be JSON with non-empty \"command\""})
		return
	}
	if a.hub == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "agent hub not available"})
		return
	}
	payload := map[string]interface{}{"server_id": id, "command": body.Command}
	if !a.hub.SendCommand(sv.NodeID, "server_command", payload) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "node not connected"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "sent"})
}

func (a *API) ServerDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sv := a.store.ServerByID(id)
	if sv != nil && !a.requireNetworkAccess(w, r, a.serverNetworkID(sv)) {
		return
	}
	a.store.ServerDelete(id)
	if sv != nil && sv.ProxyGroupID != "" {
		go cloudflare.SyncSRV(a.store, sv.ProxyGroupID)
	}
	if sv != nil {
		a.store.RecordAnalyticsEvent(&types.AnalyticsEvent{
			Type:      "server_deleted",
			NetworkID: a.serverNetworkID(sv),
			ServerID:  sv.ID,
			Server:    sv.Name,
			NodeID:    sv.NodeID,
			Message:   "Server deleted",
		})
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) ServerUpdate(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	sv := a.store.ServerByID(id)
	if sv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, a.serverNetworkID(sv)) {
		return
	}
	var body struct {
		Group     string `json:"group"`
		Name      string `json:"name"`
		ShortCode string `json:"short_code"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)
	if body.Group != "" {
		a.store.ServerSetGroup(id, body.Group)
	}
	if body.Name != "" {
		a.store.ServerSetName(id, body.Name)
	}
	if body.ShortCode != "" {
		a.store.ServerSetShortCode(id, body.ShortCode)
	}
	writeJSON(w, http.StatusOK, a.store.ServerByID(id))
}

// ServerPluginMetrics accepts runtime metrics (TPS, player count) reported by the
// Bukkit/Spigot/Paper plugin running inside a backend server, or by proxy plugins.
// Auth is via the same Bearer token mechanism used for other API calls.
func (a *API) ServerPluginMetrics(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := vars["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing server id"})
		return
	}
	var body struct {
		TPS         float64 `json:"tps"`
		PlayerCount int     `json:"player_count"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json"})
		return
	}
	if sv := a.store.ServerByID(id); sv == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server not found"})
		return
	}
	a.store.ServerUpdateFromPluginMetrics(id, body.TPS, body.PlayerCount)
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// ServerLogs returns recent log lines for a server from the persisted log file.
// GET /api/servers/{id}/logs?tail=1000
func (a *API) ServerLogs(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing server id"})
		return
	}
	// Optional: ensure caller can access this server's network.
	if sv := a.store.ServerByID(id); sv != nil {
		if sv.NetworkID != "" && !a.requireNetworkAccess(w, r, sv.NetworkID) {
			return
		}
	}
	tail := 500
	if raw := strings.TrimSpace(r.URL.Query().Get("tail")); raw != "" {
		if n, err := strconv.Atoi(raw); err == nil && n > 0 && n <= 5000 {
			tail = n
		}
	}
	dataDir := a.store.DataDir()
	if dataDir == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no logs for this server"})
		return
	}
	logPath := filepath.Join(dataDir, "logs", id+".log")
	f, err := os.Open(logPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no logs for this server"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer f.Close()
	lines, err := tailLines(f, tail)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string][]string{"lines": lines})
}

// tailLines reads up to n lines from the end of r.
func tailLines(r io.Reader, n int) ([]string, error) {
	if n <= 0 {
		return []string{}, nil
	}
	// Simple implementation: read all into memory, then take last N lines.
	// Logs are expected to be reasonably bounded per server.
	var lines []string
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 1024)
	for {
		nRead, err := r.Read(tmp)
		if nRead > 0 {
			buf = append(buf, tmp[:nRead]...)
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}
	current := ""
	for i := 0; i < len(buf); i++ {
		if buf[i] == '\n' {
			lines = append(lines, current)
			current = ""
		} else if buf[i] != '\r' {
			current += string(buf[i])
		}
	}
	if current != "" {
		lines = append(lines, current)
	}
	if len(lines) <= n {
		return lines, nil
	}
	return lines[len(lines)-n:], nil
}

func (a *API) ServersScaleGroup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Group       string `json:"group"`        // e.g. "Proxy", "Hub"
		PresetID    string `json:"preset_id"`    // preset to use for new servers
		TargetCount int    `json:"target_count"` // ensure this many servers in the group
		NodeID      string `json:"node_id"`      // optional; if set, create all on this node; else round-robin
		NetworkID   string `json:"network_id"`   // optional; when set, new servers inherit this network (recommended)
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if body.Group == "" || body.PresetID == "" || body.TargetCount < 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "group, preset_id, and target_count (>= 0) required"})
		return
	}
	current := a.store.ServersByGroup(body.Group)
	need := body.TargetCount - len(current)
	if need <= 0 {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"group": body.Group, "current": len(current), "target": body.TargetCount, "created": 0,
		})
		return
	}
	nodes := a.store.NodesList()
	if len(nodes) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no nodes available"})
		return
	}
	var nodeIDs []string
	if body.NodeID != "" {
		n := a.store.NodeByID(body.NodeID)
		if n == nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "node_id not found"})
			return
		}
		if a.nodeIsOffline(body.NodeID) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Node is offline. Start the agent on that node first."})
			return
		}
		nodeIDs = []string{body.NodeID}
	} else {
		for _, n := range nodes {
			if !a.nodeIsOffline(n.ID) {
				nodeIDs = append(nodeIDs, n.ID)
			}
		}
		if len(nodeIDs) == 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "no online nodes available"})
			return
		}
	}
	a.scalerMu.Lock()
	defer a.scalerMu.Unlock()
	preset := a.store.PresetByID(body.PresetID)
	created := 0
	for {
		current = a.store.ServersByGroup(body.Group)
		need = body.TargetCount - len(current)
		if need <= 0 {
			break
		}
		nodeID := nodeIDs[created%len(nodeIDs)]
		ordinal := len(current) + 1
		name := body.Group + "-" + strconv.Itoa(ordinal)
		sv, err := a.store.ServerCreate(name, body.PresetID, nodeID, 0, body.Group, body.NetworkID, "", "", "")
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
			return
		}
		created++
		// Auto-start only if node is still online
		if !a.nodeIsOffline(sv.NodeID) && a.hub != nil && preset != nil {
			a.store.ServerSetStatus(sv.ID, "starting")
			payload := map[string]interface{}{"server_id": sv.ID, "preset": preset, "port": sv.Port}
			if a.store.GetSettings().AutoPortForwardUPnP {
				payload["port_forward_upnp"] = true
			}
			a.hub.SendCommand(sv.NodeID, "start_server", payload)
		}
	}
	current = a.store.ServersByGroup(body.Group)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"group": body.Group, "current": len(current), "target": body.TargetCount, "created": created,
	})
}

// Networks
func (a *API) NetworksList(w http.ResponseWriter, r *http.Request) {
	list := a.store.NetworksList()
	out := make([]*types.Network, len(list))
	p := principalFromRequest(r)
	j := 0
	for i, n := range list {
		_ = i
		if p != nil && !p.IsAdmin() && !p.CanAccessNetwork(n.ID) {
			continue
		}
		out[j] = maskNetworkCloudflareToken(n)
		j++
	}
	writeJSON(w, http.StatusOK, out[:j])
}

func (a *API) networkForAPI(id string) *types.Network {
	n := a.store.NetworkByID(id)
	if n == nil {
		return nil
	}
	return maskNetworkCloudflareToken(n)
}

func maskNetworkCloudflareToken(n *types.Network) *types.Network {
	if n == nil {
		return nil
	}
	cp := *n
	if cp.CloudflareSRV != nil && cp.CloudflareSRV.APIToken != "" {
		cf := *cp.CloudflareSRV
		cf.APIToken = "***"
		cp.CloudflareSRV = &cf
	}
	return &cp
}

func (a *API) NetworkGet(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if !a.requireNetworkAccess(w, r, id) {
		return
	}
	n := a.networkForAPI(id)
	if n == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "network not found"})
		return
	}
	writeJSON(w, http.StatusOK, n)
}

func (a *API) NetworkCreate(w http.ResponseWriter, r *http.Request) {
	var n types.Network
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if n.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name required"})
		return
	}
	p := principalFromRequest(r)
	if p != nil && !p.IsAdmin() {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	out, err := a.store.NetworkCreate(&n)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *API) NetworkUpdate(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if !a.requireNetworkAccess(w, r, id) {
		return
	}
	var n types.Network
	if err := json.NewDecoder(r.Body).Decode(&n); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	n.ID = id
	if err := a.store.NetworkUpdate(&n); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "network not found"})
		return
	}
	if n.CloudflareSRV != nil && n.CloudflareSRV.Enabled && n.CloudflareSRV.ProxyGroupID != "" {
		go cloudflare.SyncSRV(a.store, n.CloudflareSRV.ProxyGroupID)
	}
	writeJSON(w, http.StatusOK, a.networkForAPI(id))
}

func (a *API) NetworkDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if !a.requireNetworkAccess(w, r, id) {
		return
	}
	a.store.NetworkDelete(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Server Groups
func (a *API) ServerGroupsList(w http.ResponseWriter, r *http.Request) {
	list := a.store.ServerGroupsList()
	if networkID := r.URL.Query().Get("network_id"); networkID != "" {
		if !a.requireNetworkAccess(w, r, networkID) {
			return
		}
		list = a.store.ServerGroupsByNetwork(networkID)
	}
	p := principalFromRequest(r)
	if p != nil && !p.IsAdmin() {
		filtered := make([]*types.ServerGroup, 0, len(list))
		for _, g := range list {
			if p.CanAccessNetwork(g.NetworkID) {
				filtered = append(filtered, g)
			}
		}
		list = filtered
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) ServerGroupGet(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	g := a.store.ServerGroupByID(id)
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server group not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (a *API) ServerGroupCreate(w http.ResponseWriter, r *http.Request) {
	var g types.ServerGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if g.Name == "" || g.PresetID == "" || g.NetworkID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name, preset_id, network_id required"})
		return
	}
	if !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	out, err := a.store.ServerGroupCreate(&g)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *API) ServerGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var g types.ServerGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	g.ID = id
	existing := a.store.ServerGroupByID(id)
	if existing == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server group not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, existing.NetworkID) || !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	if err := a.store.ServerGroupUpdate(&g); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "server group not found"})
		return
	}
	writeJSON(w, http.StatusOK, a.store.ServerGroupByID(id))
}

func (a *API) ServerGroupDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	g := a.store.ServerGroupByID(id)
	if g != nil && !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	a.store.ServerGroupDelete(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// Proxy Groups
func (a *API) ProxyGroupsList(w http.ResponseWriter, r *http.Request) {
	list := a.store.ProxyGroupsList()
	if networkID := r.URL.Query().Get("network_id"); networkID != "" {
		if !a.requireNetworkAccess(w, r, networkID) {
			return
		}
		list = a.store.ProxyGroupsByNetwork(networkID)
	}
	p := principalFromRequest(r)
	if p != nil && !p.IsAdmin() {
		filtered := make([]*types.ProxyGroup, 0, len(list))
		for _, g := range list {
			if p.CanAccessNetwork(g.NetworkID) {
				filtered = append(filtered, g)
			}
		}
		list = filtered
	}
	writeJSON(w, http.StatusOK, list)
}

func (a *API) ProxyGroupGet(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	g := a.store.ProxyGroupByID(id)
	if g == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy group not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	writeJSON(w, http.StatusOK, g)
}

func (a *API) ProxyGroupCreate(w http.ResponseWriter, r *http.Request) {
	var g types.ProxyGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if g.Name == "" || g.PresetID == "" || g.NetworkID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name, preset_id, network_id required"})
		return
	}
	if !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	out, err := a.store.ProxyGroupCreate(&g)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *API) ProxyGroupUpdate(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var g types.ProxyGroup
	if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	g.ID = id
	existing := a.store.ProxyGroupByID(id)
	if existing == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy group not found"})
		return
	}
	if !a.requireNetworkAccess(w, r, existing.NetworkID) || !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	if err := a.store.ProxyGroupUpdate(&g); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "proxy group not found"})
		return
	}
	writeJSON(w, http.StatusOK, a.store.ProxyGroupByID(id))
}

func (a *API) ProxyGroupDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	g := a.store.ProxyGroupByID(id)
	if g != nil && !a.requireNetworkAccess(w, r, g.NetworkID) {
		return
	}
	a.store.ProxyGroupDelete(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (a *API) PresetsList(w http.ResponseWriter, r *http.Request) {
	list := a.store.PresetsList()
	writeJSON(w, http.StatusOK, list)
}

func (a *API) PresetGet(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	p := a.store.PresetByID(id)
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "preset not found"})
		return
	}
	writeJSON(w, http.StatusOK, p)
}

func (a *API) PresetCreate(w http.ResponseWriter, r *http.Request) {
	var p struct {
		Name          string            `json:"name"`
		Version       string            `json:"version"`
		Type          string            `json:"type"`
		JarPath       string            `json:"jar_path"`
		JavaExec      string            `json:"java_exec"`
		JVMFlags      string            `json:"jvm_flags"`
		MemoryMin     string            `json:"memory_min"`
		MemoryMax     string            `json:"memory_max"`
		StartupArgs   string            `json:"startup_args"`
		DockerImage   string            `json:"docker_image"`
		DockerRunArgs string            `json:"docker_run_args"`
		DefaultGroup  string            `json:"default_group"`
		Env           map[string]string `json:"env"`
		PackageID     string            `json:"package_id"` // from BuildImage; links stored package to this preset
	}
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	if p.Type == "" {
		p.Type = "java"
	}
	preset := &types.Preset{
		Name: p.Name, Version: p.Version, Type: p.Type,
		JarPath: p.JarPath, JavaExec: p.JavaExec, JVMFlags: p.JVMFlags,
		MemoryMin: p.MemoryMin, MemoryMax: p.MemoryMax, StartupArgs: p.StartupArgs,
		DockerImage: p.DockerImage, DockerRunArgs: p.DockerRunArgs,
		DefaultGroup: p.DefaultGroup, Env: p.Env,
	}
	out, err := a.store.PresetCreate(preset)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	// If BuildImage returned a package_id, move it to the preset's package path so nodes can download it.
	if p.PackageID != "" {
		dataDir := a.store.DataDir()
		tmpPath := filepath.Join(dataDir, "packages", "tmp", p.PackageID+".zip")
		destPath := filepath.Join(dataDir, "packages", out.ID+".zip")
		_ = os.MkdirAll(filepath.Join(dataDir, "packages"), 0750)
		if err := os.Rename(tmpPath, destPath); err != nil {
			// fallback: copy then remove (e.g. cross-filesystem)
			if data, err := os.ReadFile(tmpPath); err == nil && os.WriteFile(destPath, data, 0640) == nil {
				_ = os.Remove(tmpPath)
			}
		}
	}
	writeJSON(w, http.StatusCreated, out)
}

func (a *API) PresetUpdate(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	var p types.Preset
	if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	p.ID = id
	if err := a.store.PresetUpdate(&p); err != nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "preset not found"})
		return
	}
	writeJSON(w, http.StatusOK, a.store.PresetByID(id))
}

func (a *API) PresetDelete(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	a.store.PresetDelete(id)
	_ = os.Remove(filepath.Join(a.store.DataDir(), "packages", id+".zip"))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

// PresetPackage serves the stored build package (ZIP) for a preset so agents can download and build the image when missing.
// GET /api/presets/:id/package. Returns 404 if no package is stored (e.g. preset was created manually).
func (a *API) PresetPackage(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if a.store.PresetByID(id) == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "preset not found"})
		return
	}
	pkgPath := filepath.Join(a.store.DataDir(), "packages", id+".zip")
	f, err := os.Open(pkgPath)
	if err != nil {
		if os.IsNotExist(err) {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "no package for this preset"})
			return
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename=package.zip")
	http.ServeContent(w, r, "package.zip", info.ModTime(), f)
}

// PresetPackageUpload stores a build package for an existing preset so nodes can auto-download and build.
// POST /api/presets/:id/package with multipart form "file" (ZIP or tar.gz). Pterodactyl-style .tar.gz is accepted and converted to ZIP.
func (a *API) PresetPackageUpload(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if a.store.PresetByID(id) == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "preset not found"})
		return
	}
	const maxSize = 200 << 20 // 200 MB
	if err := r.ParseMultipartForm(maxSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form: " + err.Error()})
		return
	}
	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file (ZIP or tar.gz) is required: " + err.Error()})
		return
	}
	defer file.Close()
	body, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read file: " + err.Error()})
		return
	}
	zipBytes, err := ValidateAndNormalizePackage(body)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	packagesDir := filepath.Join(a.store.DataDir(), "packages")
	if err := os.MkdirAll(packagesDir, 0750); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	destPath := filepath.Join(packagesDir, id+".zip")
	if err := os.WriteFile(destPath, zipBytes, 0640); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "uploaded"})
}
