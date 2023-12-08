import "pe"

rule DebuggerCheck__QueryInfo : AntiDebug DebuggerCheck
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Checks for the presence of QueryInformationProcess function, commonly used for anti-debugging"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "QueryInformationProcess"

	condition:
		any of them
}
