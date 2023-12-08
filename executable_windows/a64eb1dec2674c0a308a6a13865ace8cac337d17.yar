import "pe"

rule SEH__v3 : AntiDebug SEH
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects the presence of SEH-based anti-debugging techniques"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "____except__handler3"
		$ = "____local__unwind3"

	condition:
		any of them
}
