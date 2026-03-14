package auth

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email,omitempty"`
	PasswordEnc string    `json:"password_enc"` // AES-256 encrypted bcrypt hash
	Role        string    `json:"role"`         // "admin" or "member"
	Permissions []string  `json:"permissions,omitempty"`
	NetworkIDs  []string  `json:"network_ids,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type SafeUser struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	Email       string    `json:"email,omitempty"`
	Role        string    `json:"role"`
	Permissions []string  `json:"permissions,omitempty"`
	NetworkIDs  []string  `json:"network_ids,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

type Principal struct {
	UserID      string
	Username    string
	Role        string
	Permissions map[string]bool
	NetworkIDs  map[string]bool
}

type Secrets struct {
	AgentTokens map[string]string `json:"agent_tokens"` // token -> node ID (optional, for revocation)
	APIToken    string            `json:"api_token"`    // optional API auth
	JWTSecret   string            `json:"jwt_secret"`
	Users       map[string]*User  `json:"users"` // username -> user
	SetupComplete bool            `json:"setup_complete"`
}

type Auth struct {
	mu      sync.RWMutex
	secrets Secrets
	path    string
}

func New(secretsPath string) (*Auth, error) {
	a := &Auth{
		path: secretsPath,
		secrets: Secrets{
			AgentTokens: make(map[string]string),
			Users:       make(map[string]*User),
		},
	}
	if err := a.load(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return a, nil
}

func (a *Auth) load() error {
	data, err := os.ReadFile(a.path)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, &a.secrets); err != nil {
		return err
	}
	if a.secrets.AgentTokens == nil {
		a.secrets.AgentTokens = make(map[string]string)
	}
	if a.secrets.Users == nil {
		a.secrets.Users = make(map[string]*User)
	}
	if _, ok := a.secrets.Users["admin"]; !ok {
		now := time.Now()
		a.secrets.Users["admin"] = &User{
			ID:          uuid.New().String(),
			Username:    "admin",
			Role:        "admin",
			Permissions: []string{"*"},
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	}
	if a.secrets.Users["admin"] != nil && strings.TrimSpace(a.secrets.Users["admin"].PasswordEnc) != "" {
		a.secrets.SetupComplete = true
	} else if a.secrets.Users["admin"] != nil {
		// Migrate: admin exists but no password; force setup wizard (only touches secrets file).
		a.secrets.SetupComplete = false
		_ = a.writeSecretsFile()
	}
	return nil
}

// writeSecretsFile persists secrets to disk without locking. Only use during load() or when already holding a.mu.
func (a *Auth) writeSecretsFile() error {
	data, err := json.MarshalIndent(a.secrets, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(a.path, data, 0600)
}

func (a *Auth) save() error {
	a.mu.RLock()
	defer a.mu.RUnlock()
	data, err := json.MarshalIndent(a.secrets, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	_ = os.MkdirAll(dir, 0700)
	return os.WriteFile(a.path, data, 0600)
}

// ValidateAgentToken returns true if the token is valid for agent auth.
func (a *Auth) ValidateAgentToken(token string) bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	// If we have a list, token must be in it. Otherwise we have a single token.
	if len(a.secrets.AgentTokens) > 0 {
		_, ok := a.secrets.AgentTokens[token]
		return ok
	}
	return a.secrets.APIToken != "" && a.secrets.APIToken == token
}

// EnsureSecrets generates token and saves if file doesn't exist.
func (a *Auth) EnsureSecrets() (agentToken string, err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.secrets.AgentTokens == nil {
		a.secrets.AgentTokens = make(map[string]string)
	}
	if a.secrets.Users == nil {
		a.secrets.Users = make(map[string]*User)
	}
	if a.secrets.APIToken == "" {
		token := "pyza_" + uuid.New().String()
		a.secrets.APIToken = token
		a.secrets.AgentTokens[token] = ""
	}
	if a.secrets.JWTSecret == "" {
		a.secrets.JWTSecret = uuid.New().String() + uuid.New().String()
	}
	// Bootstrap admin account shell; password is set by initial setup wizard.
	if len(a.secrets.Users) == 0 {
		now := time.Now()
		a.secrets.Users["admin"] = &User{
			ID:          uuid.New().String(),
			Username:    "admin",
			Role:        "admin",
			Permissions: []string{"*"},
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		a.secrets.SetupComplete = false
	}
	data, err := json.MarshalIndent(a.secrets, "", "  ")
	if err != nil {
		return "", err
	}
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	if err := os.WriteFile(a.path, data, 0600); err != nil {
		return "", err
	}
	return a.secrets.APIToken, nil
}

// GetAPIToken returns the API token for dashboard/CLI.
func (a *Auth) GetAPIToken() string {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.secrets.APIToken
}

func (a *Auth) Login(username, password string) (string, *SafeUser, error) {
	if a.NeedsSetup() {
		return "", nil, errors.New("initial setup required")
	}
	a.mu.RLock()
	u := a.secrets.Users[username]
	jwtSecret := a.secrets.JWTSecret
	apiToken := a.secrets.APIToken
	a.mu.RUnlock()
	if u == nil {
		return "", nil, errors.New("invalid username or password")
	}
	// Admin must use the password set in setup; agent/API token cannot be used for dashboard login.
	if username == "admin" && apiToken != "" && password == apiToken {
		return "", nil, errors.New("admin must sign in with the password set in setup; agent token cannot be used for login")
	}
	hash, err := a.decryptHash(u.PasswordEnc)
	if err != nil {
		return "", nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)); err != nil {
		return "", nil, errors.New("invalid username or password")
	}
	token, err := signJWT(jwtSecret, u)
	if err != nil {
		return "", nil, err
	}
	return token, toSafeUser(u), nil
}

func (a *Auth) NeedsSetup() bool {
	a.mu.RLock()
	defer a.mu.RUnlock()
	admin := a.secrets.Users["admin"]
	if admin == nil {
		return true
	}
	if strings.TrimSpace(admin.PasswordEnc) == "" {
		return true
	}
	return !a.secrets.SetupComplete
}

func (a *Auth) SetupStatus() map[string]interface{} {
	a.mu.RLock()
	defer a.mu.RUnlock()
	admin := a.secrets.Users["admin"]
	hasAdminPassword := admin != nil && strings.TrimSpace(admin.PasswordEnc) != ""
	required := a.NeedsSetup()
	if !required && !hasAdminPassword {
		required = true
	}
	return map[string]interface{}{
		"required":            required,
		"has_admin_password":  hasAdminPassword,
		"quick_guide_enabled": true,
	}
}

func sanitizePassword(pw string) string {
	pw = strings.TrimSpace(pw)
	pw = strings.Map(func(r rune) rune {
		// Drop invisible/format chars like zero-width spaces.
		if unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, pw)
	return pw
}

func validateStrongPassword(pw string) error {
	pw = sanitizePassword(pw)
	if pw == "" {
		return errors.New("password cannot be empty")
	}
	if len([]rune(pw)) < 10 {
		return errors.New("password must be at least 10 characters")
	}
	hasLetter := false
	hasNumber := false
	for _, r := range pw {
		if unicode.IsLetter(r) {
			hasLetter = true
		}
		if unicode.IsDigit(r) {
			hasNumber = true
		}
	}
	if !hasLetter || !hasNumber {
		return errors.New("password must include letters and numbers")
	}
	return nil
}

func (a *Auth) CompleteInitialSetup(adminPassword string) error {
	adminPassword = sanitizePassword(adminPassword)
	if err := validateStrongPassword(adminPassword); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.secrets.Users == nil {
		a.secrets.Users = make(map[string]*User)
	}
	admin := a.secrets.Users["admin"]
	if admin == nil {
		now := time.Now()
		admin = &User{
			ID:          uuid.New().String(),
			Username:    "admin",
			Role:        "admin",
			Permissions: []string{"*"},
			CreatedAt:   now,
			UpdatedAt:   now,
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(adminPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	enc, err := a.encryptHash(string(hash))
	if err != nil {
		return err
	}
	admin.PasswordEnc = enc
	admin.UpdatedAt = time.Now()
	a.secrets.Users["admin"] = admin
	a.secrets.SetupComplete = true
	data, err := json.MarshalIndent(a.secrets, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(a.path, data, 0600)
}

func (a *Auth) ValidateJWT(token string) (*Principal, error) {
	a.mu.RLock()
	secret := a.secrets.JWTSecret
	a.mu.RUnlock()
	return verifyJWT(secret, token)
}

func (a *Auth) ListUsers() []SafeUser {
	a.mu.RLock()
	defer a.mu.RUnlock()
	out := make([]SafeUser, 0, len(a.secrets.Users))
	for _, u := range a.secrets.Users {
		out = append(out, *toSafeUser(u))
	}
	return out
}

func (a *Auth) UpsertUser(username, password, role, email string, permissions, networkIDs []string) (*SafeUser, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if strings.TrimSpace(username) == "" {
		return nil, errors.New("username required")
	}
	if role != "admin" && role != "member" {
		return nil, errors.New("role must be admin or member")
	}
	if a.secrets.Users == nil {
		a.secrets.Users = make(map[string]*User)
	}
	now := time.Now()
	u := a.secrets.Users[username]
	if u == nil {
		if password == "" {
			return nil, errors.New("password required for new user")
		}
		u = &User{
			ID:        uuid.New().String(),
			Username:  username,
			CreatedAt: now,
		}
	}
	u.Email = strings.TrimSpace(email)
	if password != "" {
		password = sanitizePassword(password)
		if err := validateStrongPassword(password); err != nil {
			return nil, err
		}
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return nil, err
		}
		enc, err := a.encryptHash(string(hash))
		if err != nil {
			return nil, err
		}
		u.PasswordEnc = enc
	}
	u.Role = role
	u.Permissions = dedupeStrings(permissions)
	u.NetworkIDs = dedupeStrings(networkIDs)
	u.UpdatedAt = now
	a.secrets.Users[username] = u
	data, err := json.MarshalIndent(a.secrets, "", "  ")
	if err != nil {
		return nil, err
	}
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(a.path, data, 0600); err != nil {
		return nil, err
	}
	return toSafeUser(u), nil
}

func (a *Auth) DeleteUser(username string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if username == "admin" {
		return errors.New("cannot delete admin")
	}
	delete(a.secrets.Users, username)
	data, err := json.MarshalIndent(a.secrets, "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(a.path, data, 0600)
}

func toSafeUser(u *User) *SafeUser {
	return &SafeUser{
		ID:          u.ID,
		Username:    u.Username,
		Email:       u.Email,
		Role:        u.Role,
		Permissions: append([]string{}, u.Permissions...),
		NetworkIDs:  append([]string{}, u.NetworkIDs...),
		CreatedAt:   u.CreatedAt,
		UpdatedAt:   u.UpdatedAt,
	}
}

func (a *Auth) aesKey() []byte {
	seed := os.Getenv("PYZANODE_MASTER_KEY")
	if seed == "" {
		seed = a.secrets.APIToken
	}
	sum := sha256.Sum256([]byte(seed))
	return sum[:]
}

func (a *Auth) encryptHash(plain string) (string, error) {
	key := a.aesKey()
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nonce, nonce, []byte(plain), nil)
	return base64.RawURLEncoding.EncodeToString(ct), nil
}

func (a *Auth) decryptHash(enc string) (string, error) {
	key := a.aesKey()
	raw, err := base64.RawURLEncoding.DecodeString(enc)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("invalid encrypted password")
	}
	nonce, cipherText := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	pt, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return "", err
	}
	return string(pt), nil
}

type jwtClaims struct {
	Sub         string   `json:"sub"`
	Username    string   `json:"username"`
	Role        string   `json:"role"`
	Permissions []string `json:"permissions,omitempty"`
	NetworkIDs  []string `json:"network_ids,omitempty"`
	Iat         int64    `json:"iat"`
	Exp         int64    `json:"exp"`
}

func signJWT(secret string, u *User) (string, error) {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))
	claims := jwtClaims{
		Sub:         u.ID,
		Username:    u.Username,
		Role:        u.Role,
		Permissions: u.Permissions,
		NetworkIDs:  u.NetworkIDs,
		Iat:         time.Now().Unix(),
		Exp:         time.Now().Add(24 * time.Hour).Unix(),
	}
	bodyRaw, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(bodyRaw)
	payload := header + "." + body
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig, nil
}

func verifyJWT(secret, token string) (*Principal, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token")
	}
	payload := parts[0] + "." + parts[1]
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expected := mac.Sum(nil)
	got, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(expected, got) {
		return nil, errors.New("invalid token signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var c jwtClaims
	if err := json.Unmarshal(body, &c); err != nil {
		return nil, err
	}
	if c.Exp > 0 && time.Now().Unix() > c.Exp {
		return nil, errors.New("token expired")
	}
	p := &Principal{
		UserID:      c.Sub,
		Username:    c.Username,
		Role:        c.Role,
		Permissions: map[string]bool{},
		NetworkIDs:  map[string]bool{},
	}
	for _, perm := range c.Permissions {
		p.Permissions[perm] = true
	}
	for _, n := range c.NetworkIDs {
		p.NetworkIDs[n] = true
	}
	return p, nil
}

func (p *Principal) IsAdmin() bool {
	return p != nil && p.Role == "admin"
}

func (p *Principal) Can(permission string) bool {
	if p == nil {
		return false
	}
	if p.IsAdmin() || p.Permissions["*"] {
		return true
	}
	return p.Permissions[permission]
}

func (p *Principal) CanAccessNetwork(networkID string) bool {
	if p == nil {
		return false
	}
	if networkID == "" {
		return p.IsAdmin()
	}
	if p.IsAdmin() {
		return true
	}
	return p.NetworkIDs[networkID]
}

func dedupeStrings(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, v := range in {
		v = strings.TrimSpace(v)
		if v == "" || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
