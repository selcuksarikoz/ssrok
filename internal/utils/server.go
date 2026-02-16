package utils

func IsStandardPort(scheme, port string) bool {
	if scheme == "http" && port == "80" {
		return true
	}
	if scheme == "https" && port == "443" {
		return true
	}
	return false
}
