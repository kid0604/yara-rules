import "pe"

rule FSGv110EngdulekxtMicrosoftVisualC4xLCCWin321x
{
	meta:
		author = "malware-lu"
		description = "Detects the FSGv110EngdulekxtMicrosoftVisualC4xLCCWin321x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2C 71 1B CA EB 01 2A EB 01 65 8D 35 80 [2] 00 80 C9 84 80 C9 68 BB F4 00 00 00 EB 01 EB }

	condition:
		$a0 at pe.entry_point
}
