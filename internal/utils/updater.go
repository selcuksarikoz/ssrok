package utils

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"ssrok/internal/constants"
)

type VersionInfo struct {
	Version   string `json:"version"`
	Downloads struct {
		Darwin struct {
			Arm64 string `json:"arm64"`
			Amd64 string `json:"amd64"`
		} `json:"darwin"`
		Linux struct {
			Arm64 string `json:"arm64"`
			Amd64 string `json:"amd64"`
		} `json:"linux"`
		Windows struct {
			Amd64 string `json:"amd64"`
		} `json:"windows"`
	} `json:"downloads"`
}

func GetCurrentVersion() string {
	return constants.Version
}

func GetRemoteVersion() (*VersionInfo, error) {
	resp, err := http.Get(constants.VersionCheckURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch version info: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("version check returned status %d", resp.StatusCode)
	}

	var info VersionInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("failed to parse version JSON: %w", err)
	}

	return &info, nil
}

func IsNewerVersion(remoteVersion string) bool {
	return compareVersions(constants.Version, remoteVersion) < 0
}

func compareVersions(current, remote string) int {
	cParts := strings.Split(strings.TrimPrefix(current, "v"), ".")
	rParts := strings.Split(strings.TrimPrefix(remote, "v"), ".")

	for i := 0; i < len(cParts) && i < len(rParts); i++ {
		var c, r int
		fmt.Sscanf(cParts[i], "%d", &c)
		fmt.Sscanf(rParts[i], "%d", &r)
		if c < r {
			return -1
		}
		if c > r {
			return 1
		}
	}
	return 0
}

func RunUpdate() {
	fmt.Printf("  Current version: %s\n", constants.Version)
	fmt.Println("  Checking for updates...")

	remoteInfo, err := GetRemoteVersion()
	if err != nil {
		fmt.Printf("  %sFailed to check for updates: %s%s\n", constants.ColorYellow, err.Error(), constants.ColorReset)
		os.Exit(1)
	}

	fmt.Printf("  Latest version: %s\n", remoteInfo.Version)

	if !IsNewerVersion(remoteInfo.Version) {
		fmt.Printf("  %sYou are running the latest version!%s\n", constants.ColorGreen, constants.ColorReset)
		os.Exit(0)
	}

	fmt.Printf("  %sNew version available! Updating...%s\n", constants.ColorCyan, constants.ColorReset)

	runOSUpdate(remoteInfo)
}

func runOSUpdate(info *VersionInfo) {
	goos := runtime.GOOS
	arch := runtime.GOARCH

	var downloadURL string

	switch goos {
	case "darwin":
		if arch == "arm64" {
			downloadURL = info.Downloads.Darwin.Arm64
		} else {
			downloadURL = info.Downloads.Darwin.Amd64
		}
	case "linux":
		if arch == "arm64" {
			downloadURL = info.Downloads.Linux.Arm64
		} else {
			downloadURL = info.Downloads.Linux.Amd64
		}
	case "windows":
		downloadURL = info.Downloads.Windows.Amd64
	default:
		fmt.Printf("  %sUnsupported OS: %s%s\n", constants.ColorRed, goos, constants.ColorReset)
		os.Exit(1)
	}

	if downloadURL == "" {
		fmt.Printf("  %sNo download available for %s/%s%s\n", constants.ColorYellow, goos, arch, constants.ColorReset)
		os.Exit(1)
	}

	fmt.Printf("  Downloading from: %s\n", downloadURL)

	if goos == "darwin" {
		runBrewUpdate(info.Version)
	} else {
		runCurlUpdate(downloadURL, goos, info.Version)
	}
}

func runBrewUpdate(newVersion string) {
	fmt.Println("  Running: brew upgrade ssrok")

	cmd := exec.Command("brew", "upgrade", "ssrok")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		fmt.Printf("  %sBrew upgrade failed, trying install...%s\n", constants.ColorYellow, constants.ColorReset)
		installCmd := exec.Command("brew", "install", "ssrok")
		installCmd.Stdout = os.Stdout
		installCmd.Stderr = os.Stderr
		installCmd.Stdin = os.Stdin
		if err := installCmd.Run(); err != nil {
			fmt.Printf("  %sFailed to install via brew%s\n", constants.ColorRed, constants.ColorReset)
			os.Exit(1)
		}
	}

	fmt.Println()
	fmt.Printf("  %sUpdate to v%s complete!%s\n", constants.ColorGreen, newVersion, constants.ColorReset)
	os.Exit(0)
}

func runCurlUpdate(url, goos, newVersion string) {
	tmpDir := os.TempDir()
	var tmpFile string
	var binaryName string

	if goos == "windows" {
		binaryName = "ssrok.exe"
	} else {
		binaryName = "ssrok"
	}
	tmpFile = filepath.Join(tmpDir, binaryName)

	fmt.Printf("  Downloading to %s...\n", tmpFile)

	if err := downloadFile(url, tmpFile); err != nil {
		fmt.Printf("  %sDownload failed: %s%s\n", constants.ColorRed, err.Error(), constants.ColorReset)
		os.Exit(1)
	}

	if goos != "windows" {
		if err := os.Chmod(tmpFile, 0755); err != nil {
			fmt.Printf("  %sWarning: failed to set executable permission%s\n", constants.ColorYellow, constants.ColorReset)
		}
	}

	fmt.Println()
	fmt.Printf("  %sDownload complete!%s\n", constants.ColorGreen, constants.ColorReset)
	fmt.Printf("  Binary saved to: %s\n", tmpFile)
	fmt.Println("  Move it to your PATH to use the new version.")
	os.Exit(0)
}

func downloadFile(url, filepath string) error {
	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("bad status: %s", resp.Status)
	}

	out, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, resp.Body)
	return err
}

func CheckForUpdate() bool {
	remoteInfo, err := GetRemoteVersion()
	if err != nil {
		return false
	}
	return IsNewerVersion(remoteInfo.Version)
}
