import "pe"

rule DebuggerException__ConsoleCtrl : AntiDebug DebuggerException
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects the presence of debugger exception related to ConsoleCtrl"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "GenerateConsoleCtrlEvent"

	condition:
		any of them
}
