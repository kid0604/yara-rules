import "pe"

rule Apex30alpha500mhz
{
	meta:
		author = "malware-lu"
		description = "Detects the Apex30alpha500mhz malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5F B9 14 00 00 00 51 BE 00 10 40 00 B9 00 [2] 00 8A 07 30 06 46 E2 FB 47 59 E2 EA 68 [3] 00 C3 }

	condition:
		$a0
}
