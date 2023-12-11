import "math"
import "pe"

rule CobaltStrike_ShellCode
{
	meta:
		description = "Detect the risk of  Malware Cobalt Strike Rule 14"
		os = "windows"
		filetype = "executable"

	strings:
		$ = {8B 58 24 01 D3 66 8B 0C 4B 8B 58 1C 01 D3 8B 04 8B}
		$ = {68 6E 65 74 00 68 77 69 6E 69 54 68 4C 77 26 07 FF D5}

	condition:
		any of them
}
