import "pe"

rule ThreadControl__Context : AntiDebug ThreadControl
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects the presence of SetThreadContext function, commonly used for anti-debugging and thread control"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "SetThreadContext"

	condition:
		any of them
}
