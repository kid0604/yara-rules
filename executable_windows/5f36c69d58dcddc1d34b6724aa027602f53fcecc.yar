import "pe"

rule DebuggerException__SetConsoleCtrl : AntiDebug DebuggerException
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects the presence of SetConsoleCtrlHandler function, which can be used for anti-debugging purposes"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "SetConsoleCtrlHandler"

	condition:
		any of them
}
