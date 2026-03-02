package main

import (
	"flag"
	"fmt"
	"os"

	"ssrok/internal/client"
	"ssrok/internal/constants"
	"ssrok/internal/screen"
	"ssrok/internal/utils"
)

func main() {
	flag.Usage = func() {
		fmt.Println()
		fmt.Printf("  %s%sssrok%s %sv%s%s\n", constants.ColorBold, constants.ColorCyan, constants.ColorReset, constants.ColorBold, constants.Version, constants.ColorReset)
		fmt.Println()
		fmt.Printf("  %sUsage:%s\n", constants.ColorBold, constants.ColorReset)
		fmt.Printf("    ssrok %s<port>%s              # e.g. ssrok 3000\n", constants.ColorCyan, constants.ColorReset)
		fmt.Printf("    ssrok %s<ip>:<port>%s         # e.g. ssrok 192.168.1.100:8080\n", constants.ColorCyan, constants.ColorReset)
		fmt.Printf("    ssrok %sscreen%s              # Share your screen with a stream\n", constants.ColorCyan, constants.ColorReset)
		fmt.Println()
		fmt.Printf("  %sFlags:%s\n", constants.ColorBold, constants.ColorReset)
		flag.VisitAll(func(f *flag.Flag) {
			fmt.Printf("    -%-12s %s\n", f.Name, f.Usage)
		})
		fmt.Println()
	}

	versionFlag := flag.Bool("version", false, "show version")
	updateFlag := flag.Bool("update", false, "update ssrok via brew")
	flag.Parse()

	if *versionFlag {
		client.PrintBanner()
		os.Exit(0)
	}

	if *updateFlag {
		utils.RunUpdate()
	}

	if utils.CheckForUpdate() {
		fmt.Printf("  %s %sNew version available! Run 'ssrok -update' to update.%s\n", constants.SymbolConfetti, constants.ColorBlue, constants.ColorReset)
	}

	if len(os.Args) < 2 {
		fmt.Println(constants.MsgUsage)
		fmt.Println(constants.MsgExample)
		os.Exit(1)
	}

	arg := flag.Arg(0)
	if arg == "" && len(os.Args) > 1 {
		arg = os.Args[1]
	}

	var targetHost string
	var targetPort int
	var useTLS bool
	var isScreen bool
	var err error

	if arg == "screen" {
		isScreen = true
		
		screenCmd := flag.NewFlagSet("screen", flag.ExitOnError)
		fpsFlag := screenCmd.Int("fps", 10, "frames per second for screen share (default: 10)")
		qualityFlag := screenCmd.Int("quality", 60, "jpeg quality for screen share 1-100 (default: 60)")
		
		// Parse flags after "screen"
		screenArgs := []string{}
		for i, a := range os.Args {
			if a == "screen" {
				screenArgs = os.Args[i+1:]
				break
			}
		}
		screenCmd.Parse(screenArgs)

		targetHost = "127.0.0.1"
		port, err := screen.StartStreamServer(*fpsFlag, *qualityFlag)
		if err != nil {
			fmt.Printf("%sError starting screen server: %s%s\n", constants.ColorRed, err.Error(), constants.ColorReset)
			os.Exit(1)
		}
		targetPort = port
		useTLS = false
	} else {
		targetHost, targetPort, err = utils.ParseTarget(arg)
		if err != nil {
			fmt.Printf("%sError: %s%s\n", constants.ColorRed, err.Error(), constants.ColorReset)
			os.Exit(1)
		}
		useTLS = utils.DetectProtocol(targetHost, targetPort)
	}

	client.Start(targetHost, targetPort, useTLS, isScreen)
}
