import "pe"

rule DebuggerHiding__Thread : AntiDebug DebuggerHiding
{
	meta:
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		weight = 1
		description = "Detects debugger hiding techniques using SetInformationThread"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "SetInformationThread"

	condition:
		any of them
}
