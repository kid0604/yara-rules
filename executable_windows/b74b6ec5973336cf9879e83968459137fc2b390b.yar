import "pe"

rule SEH__vectored : AntiDebug SEH
{
	meta:
		weight = 1
		Author = "naxonez"
		reference = "https://github.com/naxonez/yaraRules/blob/master/AntiDebugging.yara"
		description = "Detects the presence of SEH vectored exception handlers, which can be used for anti-debugging"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "AddVectoredExceptionHandler"
		$ = "RemoveVectoredExceptionHandler"

	condition:
		any of them
}
