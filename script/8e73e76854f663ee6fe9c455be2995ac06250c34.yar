import "pe"

rule SEH__vba : AntiDebug SEH
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects the presence of vbaExceptHandler in the code, which can be used for anti-debugging"
		os = "windows"
		filetype = "script"

	strings:
		$ = "vbaExceptHandler"

	condition:
		any of them
}
