import "pe"

rule DebuggerCheck__GlobalFlags : AntiDebug DebuggerCheck
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Checks for the presence of NtGlobalFlags to detect debugger"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "NtGlobalFlags"

	condition:
		any of them
}
