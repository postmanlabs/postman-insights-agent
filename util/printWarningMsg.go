package util

import (
	"fmt"

	"github.com/postmanlabs/postman-insights-agent/printer"
)

const warningMessage = `
██     ██  █████  ██████  ███    ██ ██ ███    ██  ██████  
██     ██ ██   ██ ██   ██ ████   ██ ██ ████   ██ ██       
██  █  ██ ███████ ██████  ██ ██  ██ ██ ██ ██  ██ ██   ███ 
██ ███ ██ ██   ██ ██   ██ ██  ██ ██ ██ ██  ██ ██ ██    ██ 
 ███ ███  ██   ██ ██   ██ ██   ████ ██ ██   ████  ██████  
                                                          
 ______   ______   ______   ______   ______   ______ 
/_____/  /_____/  /_____/  /_____/  /_____/  /_____/ 
																										
YOU ARE USING UNDOCUMENTED FLAGS ONLY FOR DEBUGGING AND
TESTING. THESE FLAGS ARE NOT MEANT TO BY USED BY END USERS
UNLESS THEY ARE DIRECTED TO DO SO BY POSTMAN SUPPORT!!!
 ______   ______   ______   ______   ______   ______ 
/_____/  /_____/  /_____/  /_____/  /_____/  /_____/ 
																										
See below for flags and their warning:`

func PrintFlagsWarning(warningFlags map[string]string) {
	// Print banner
	printer.Warningf("%s\n", warningMessage)

	// Print flags and their warnings
	for flag, warning := range warningFlags {
		fmt.Printf("Flag: %s\tWarning: %s\n", flag, warning)
	}

	// Print new line
	fmt.Printf("\n")
}

const reproModeMessage = `Turning on the %s flag enables the Postman Insights Agent to send payload data to the Postman cloud.

The Postman Insights Agent will automatically redact values in a default list of sensitive fields, as well as any additionally specified fields.
It is your reponsibility to ensure that any additional sensitive fields are appropriately redacted.
For more information, please see: %s.

By enabling this flag you acknowledge that you have read this message and accompanying documentation, and that you both understand the risks and have appropriate permission to proceed.
`

func PrintReproModeWarning(flag string) {
	printer.Warningf(reproModeMessage,
		printer.Color.Yellow(flag),
		printer.Color.Blue("https://learning.postman.com/docs/insights/repro"))
}
