package api

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/uuid"
)

// extractArchive extracts ZIP or tar.gz (including .tgz) into dir. Uses magic bytes to detect format.
func extractArchive(body []byte, dir string) error {
	if len(body) < 2 {
		return errors.New("file too small or empty")
	}
	// ZIP: PK
	if body[0] == 0x50 && body[1] == 0x4B {
		zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
		if err != nil {
			return err
		}
		for _, f := range zr.File {
			if f.FileInfo().IsDir() {
				continue
			}
			dest := filepath.Join(dir, filepath.FromSlash(f.Name))
			rel, err := filepath.Rel(dir, dest)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			_ = os.MkdirAll(filepath.Dir(dest), 0755)
			out, err := os.Create(dest)
			if err != nil {
				continue
			}
			rc, _ := f.Open()
			_, _ = io.Copy(out, rc)
			out.Close()
			rc.Close()
		}
		return nil
	}
	// GZIP (tar.gz): 0x1f 0x8b
	if body[0] == 0x1f && body[1] == 0x8b {
		gr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			return err
		}
		defer gr.Close()
		tr := tar.NewReader(gr)
		for {
			h, err := tr.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
			if h.Typeflag == tar.TypeDir {
				continue
			}
			dest := filepath.Join(dir, filepath.FromSlash(h.Name))
			rel, err := filepath.Rel(dir, dest)
			if err != nil || strings.HasPrefix(rel, "..") {
				continue
			}
			_ = os.MkdirAll(filepath.Dir(dest), 0755)
			out, err := os.Create(dest)
			if err != nil {
				continue
			}
			_, _ = io.Copy(out, tr)
			out.Close()
		}
		return nil
	}
	return errors.New("unsupported format: use ZIP or tar.gz")
}

// dirToZip writes a directory tree to a ZIP in memory and returns the bytes.
func dirToZip(dir string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".." || strings.HasPrefix(rel, "..") {
			return nil
		}
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, err = io.Copy(w, f)
		f.Close()
		return err
	})
	if err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// ValidateAndNormalizePackage accepts ZIP or tar.gz (e.g. Pterodactyl archive) and returns ZIP bytes.
// Dockerfile is optional: if missing, the agent will auto-generate one for server-files-only packages.
// Tar.gz is converted to ZIP so the agent always receives ZIP.
func ValidateAndNormalizePackage(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, errors.New("file too small or empty")
	}
	// ZIP: validate and return as-is
	if body[0] == 0x50 && body[1] == 0x4B {
		if _, err := zip.NewReader(bytes.NewReader(body), int64(len(body))); err != nil {
			return nil, err
		}
		return body, nil
	}
	// GZIP (tar.gz / .tgz): extract and re-pack as ZIP (agent will add Dockerfile if missing)
	if body[0] == 0x1f && body[1] == 0x8b {
		dir, err := os.MkdirTemp("", "pyzanode-pkg-*")
		if err != nil {
			return nil, err
		}
		defer os.RemoveAll(dir)
		if err := extractArchive(body, dir); err != nil {
			return nil, err
		}
		return dirToZip(dir)
	}
	return nil, errors.New("unsupported format: use ZIP or tar.gz")
}

// dockerExe returns the path to the docker executable, with Windows Docker Desktop fallbacks when not in PATH.
func dockerExe() string {
	path, err := exec.LookPath("docker")
	if err == nil {
		return path
	}
	if runtime.GOOS == "windows" {
		for _, p := range []string{
			`C:\Program Files\Docker\Docker\resources\bin\docker.exe`,
			filepath.Join(os.Getenv("ProgramFiles"), "Docker", "Docker", "resources", "bin", "docker.exe"),
			filepath.Join(os.Getenv("ProgramFiles(x86)"), "Docker", "Docker", "resources", "bin", "docker.exe"),
		} {
			if p == "" {
				continue
			}
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return "docker"
}

// BuildPackage: form file can be ZIP or tar.gz (.tgz) for Pterodactyl compatibility.
// POST /api/presets/build-package with multipart form: file (ZIP or tar.gz), name, version, base_image, memory, port, jar_name.
func (a *API) BuildPackage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const maxFormSize = 200 << 20 // 200 MB
	if err := r.ParseMultipartForm(maxFormSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form: " + err.Error()})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	version := strings.TrimSpace(r.FormValue("version"))
	baseImage := strings.TrimSpace(r.FormValue("base_image"))
	memory := strings.TrimSpace(r.FormValue("memory"))
	port := strings.TrimSpace(r.FormValue("port"))
	jarName := strings.TrimSpace(r.FormValue("jar_name"))
	if name == "" || baseImage == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and base_image are required"})
		return
	}
	if memory == "" {
		memory = "2G"
	}
	if port == "" {
		port = "25565"
	}
	if jarName == "" {
		jarName = "server.jar"
	}

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file (ZIP or tar.gz) is required: " + err.Error()})
		return
	}
	defer file.Close()

	dir, err := os.MkdirTemp("", "pyzanode-build-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "temp dir: " + err.Error()})
		return
	}
	defer os.RemoveAll(dir)

	body, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read file: " + err.Error()})
		return
	}
	if err := extractArchive(body, dir); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid archive (use ZIP or tar.gz): " + err.Error()})
		return
	}

	// Write Dockerfile
	dockerfile := `FROM ` + baseImage + `
WORKDIR /server
COPY . /server
ENV MEMORY=` + memory + `
EXPOSE ` + port + `
ENTRYPOINT ["java", "-Xms` + memory + `", "-Xmx` + memory + `", "-jar", "` + jarName + `", "nogui"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write Dockerfile: " + err.Error()})
		return
	}

	// Write pyzanode.json (package manifest)
	manifest := map[string]string{
		"name":       name,
		"version":    version,
		"base_image": baseImage,
		"memory":     memory,
		"port":       port,
		"jar_name":   jarName,
	}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "pyzanode.json"), manifestBytes, 0644)

	// Create output ZIP
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		if rel == "." {
			return nil
		}
		w, err := zw.Create(rel)
		if err != nil {
			return err
		}
		f, _ := os.Open(path)
		_, _ = io.Copy(w, f)
		f.Close()
		return nil
	})
	if walkErr != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "zip walk: " + walkErr.Error()})
		return
	}
	if err := zw.Close(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "zip close: " + err.Error()})
		return
	}

	// Return ZIP
	filename := name + "-" + version + ".zip"
	if version == "" {
		filename = name + ".zip"
	}
	filename = strings.ReplaceAll(filename, " ", "-")
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	_, _ = w.Write(buf.Bytes())
}

// BuildImage runs the same steps as BuildPackage but then runs `docker build` on the controller
// and returns the image name. Requires Docker on the controller host.
// POST /api/presets/build-image with same multipart form as build-package.
// Returns JSON { "image": "name:version" }. On failure returns 4xx/5xx with error message.
func (a *API) BuildImage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	const maxFormSize = 200 << 20 // 200 MB
	if err := r.ParseMultipartForm(maxFormSize); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid form: " + err.Error()})
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	version := strings.TrimSpace(r.FormValue("version"))
	baseImage := strings.TrimSpace(r.FormValue("base_image"))
	memory := strings.TrimSpace(r.FormValue("memory"))
	port := strings.TrimSpace(r.FormValue("port"))
	jarName := strings.TrimSpace(r.FormValue("jar_name"))
	if name == "" || baseImage == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "name and base_image are required"})
		return
	}
	if memory == "" {
		memory = "2G"
	}
	if port == "" {
		port = "25565"
	}
	if jarName == "" {
		jarName = "server.jar"
	}
	imageTag := name + ":" + version
	if version == "" {
		imageTag = name + ":latest"
	}
	// Sanitize for docker tag (lowercase, alphanumeric, hyphen, underscore, colon)
	imageTag = strings.ToLower(strings.ReplaceAll(imageTag, " ", "-"))

	file, _, err := r.FormFile("file")
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "file (ZIP or tar.gz) is required: " + err.Error()})
		return
	}
	defer file.Close()

	dir, err := os.MkdirTemp("", "pyzanode-build-*")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "temp dir: " + err.Error()})
		return
	}
	defer os.RemoveAll(dir)

	body, err := io.ReadAll(file)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read file: " + err.Error()})
		return
	}
	if err := extractArchive(body, dir); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid archive (use ZIP or tar.gz): " + err.Error()})
		return
	}

	dockerfile := `FROM ` + baseImage + `
WORKDIR /server
COPY . /server
ENV MEMORY=` + memory + `
EXPOSE ` + port + `
ENTRYPOINT ["java", "-Xms` + memory + `", "-Xmx` + memory + `", "-jar", "` + jarName + `", "nogui"]
`
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0644); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "write Dockerfile: " + err.Error()})
		return
	}
	manifest := map[string]string{"name": name, "version": version, "base_image": baseImage, "memory": memory, "port": port, "jar_name": jarName}
	manifestBytes, _ := json.MarshalIndent(manifest, "", "  ")
	_ = os.WriteFile(filepath.Join(dir, "pyzanode.json"), manifestBytes, 0644)

	cmd := exec.Command(dockerExe(), "build", "-t", imageTag, ".")
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		errMsg := "docker build failed: " + err.Error()
		outStr := string(out)
		if strings.Contains(errMsg, "failed to connect") || strings.Contains(errMsg, "daemon") || strings.Contains(outStr, "failed to connect") || strings.Contains(outStr, "daemon") {
			errMsg += ". Make sure Docker Desktop (or the Docker daemon) is running on this machine."
		}
		writeJSON(w, http.StatusInternalServerError, map[string]string{
			"error": errMsg,
			"log":   outStr,
		})
		return
	}

	// Save build package so nodes can auto-download and build when the image is missing.
	var packageID string
	packagesDir := filepath.Join(a.store.DataDir(), "packages")
	tmpDir := filepath.Join(packagesDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0750); err == nil {
		var zipBuf bytes.Buffer
		zw := zip.NewWriter(&zipBuf)
		walkErr := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info.IsDir() {
				return err
			}
			rel, _ := filepath.Rel(dir, path)
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			w, err := zw.Create(rel)
			if err != nil {
				return err
			}
			f, _ := os.Open(path)
			_, _ = io.Copy(w, f)
			f.Close()
			return nil
		})
		if walkErr == nil {
			_ = zw.Close()
			packageID = uuid.New().String()
			pkgPath := filepath.Join(tmpDir, packageID+".zip")
			if os.WriteFile(pkgPath, zipBuf.Bytes(), 0640) == nil {
				// package_id returned so frontend can pass it to PresetCreate
			}
		}
	}

	resp := map[string]string{"image": imageTag}
	if packageID != "" {
		resp["package_id"] = packageID
	}
	writeJSON(w, http.StatusOK, resp)
}
