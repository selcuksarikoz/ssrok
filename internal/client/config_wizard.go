package client

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"ssrok/internal/constants"
	"ssrok/internal/types"
	"ssrok/internal/utils"
)

// RunConfigWizard executes the interactive setup for the tunnel client
func RunConfigWizard(targetHost string, targetPort int, useTLS bool) types.ConfigRequest {
	reader := bufio.NewReader(os.Stdin)

	PrintStep(1, "Local server configuration")
	PrintHint("Target: " + targetHost + ":" + strconv.Itoa(targetPort))
	fmt.Printf("  %sProtocol:%s ", constants.ColorBold, constants.ColorReset)

	if useTLS {
		fmt.Printf("%sHTTPS (auto-detected)%s\n", constants.ColorGreen, constants.ColorReset)
	} else {
		fmt.Printf("HTTP (auto-detected)\n")
	}

	PrintStep(2, "Password (optional)")
	PrintHint("Empty password still requires clicking 'Access' on login page")
	fmt.Printf("  %sPassword:%s ", constants.ColorBold, constants.ColorReset)
	password, _ := reader.ReadString('\n')
	password = strings.TrimSpace(password)

	fmt.Println()
	fmt.Println()

	PrintStep(3, "Rate limit (0 = unlimited)")
	fmt.Printf("  %sReq/min [%d]:%s ", constants.ColorBold, constants.DefaultRateLimit, constants.ColorReset)
	rateLimitStr, _ := reader.ReadString('\n')
	rateLimitStr = strings.TrimSpace(rateLimitStr)

	rateLimit := constants.DefaultRateLimit
	if rateLimitStr != "" {
		rl, err := strconv.Atoi(rateLimitStr)
		if err == nil && rl >= 0 {
			rateLimit = rl
			if rateLimit == 0 {
				PrintHint(ColorYellow + "unlimited" + constants.ColorReset)
			} else {
				PrintHint(fmt.Sprintf("-> %d req/min per IP", rateLimit))
			}
		} else {
			PrintHint(fmt.Sprintf("-> default: %d req/min", constants.DefaultRateLimit))
		}
	}
	fmt.Println()

	PrintStep(4, "Duration (5-1440 min)")
	fmt.Printf("  %sMinutes [60]:%s ", constants.ColorBold, constants.ColorReset)
	durationStr, _ := reader.ReadString('\n')
	durationStr = strings.TrimSpace(durationStr)

	expiresIn := constants.SessionDuration
	if durationStr != "" {
		mins, err := strconv.Atoi(durationStr)
		if err == nil && mins > 0 {
			expiresIn = utils.ParseDuration(mins)
			if expiresIn < constants.MinSessionDuration {
				expiresIn = constants.MinSessionDuration
				PrintHint(fmt.Sprintf("-> clamped to %s", expiresIn))
			} else if expiresIn > constants.MaxSessionDuration {
				expiresIn = constants.MaxSessionDuration
				PrintHint(fmt.Sprintf("-> clamped to %s", expiresIn))
			} else {
				PrintHint(fmt.Sprintf("-> %d min", mins))
			}
		}
	}
	fmt.Println()

	return types.ConfigRequest{
		Port:      targetPort,
		Password:  password,
		RateLimit: rateLimit,
		UseTLS:    useTLS,
		E2EE:      true,
		ExpiresIn: expiresIn,
	}
}
