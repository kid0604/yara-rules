import "pe"

rule SEH__v4 : AntiDebug SEH
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects Structured Exception Handling (SEH) anti-debugging techniques"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "____except__handler4"
		$ = "____local__unwind4"
		$ = "__XcptFilter"

	condition:
		any of them
}
