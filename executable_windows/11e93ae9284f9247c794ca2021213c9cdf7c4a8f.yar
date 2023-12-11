import "pe"

rule MALWARE_Win_DLInjector03
{
	meta:
		author = "ditekSHen"
		description = "Detects unknown loader / injector"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "LOADER ERROR" fullword ascii
		$s1 = "_ZN6curlpp10OptionBaseC2E10CURLoption" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
