import "pe"

rule DebuggerCheck__PEB : AntiDebug DebuggerCheck
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Checks for the presence of a debugger using PEB"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "IsDebugged"

	condition:
		any of them
}
