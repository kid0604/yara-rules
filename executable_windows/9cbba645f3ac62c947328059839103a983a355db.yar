import "pe"
import "math"

rule CobaltStrike_Payload
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 15"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "%c%c%c%c%c%c%c%c%cMSSE-%d-server" fullword ascii
		$ = {B9 AA 26 00 00 31 D2 C7 44 24 28 5C 00 00 00 C7 44 24 24 65 00 00 00 C7 44 24 20 70 00 00 00 C7 44 24 1C 69 00 00 00 C7 44 24 18 70 00 00 00 F7 F1 C7 44 24 14 5C 00 00 00 C7 44 24 10 2E 00 00 00 C7 44 24 0C 5C 00 00 00 C7 44 24 08 5C 00 00 00 C7 44 24 04 44 40 40 00 C7 04 24 F0 53 40 00 89 54 24}

	condition:
		any of them
}
