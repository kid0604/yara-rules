import "pe"

rule DebuggerHiding__Active : AntiDebug DebuggerHiding
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects active debugger hiding techniques"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "DebugActiveProcess"

	condition:
		any of them
}
