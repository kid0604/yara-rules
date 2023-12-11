import "pe"

rule PEiDBundlev102v103BoBBobSoft
{
	meta:
		author = "malware-lu"
		description = "Detects PE files that are packed with BoBSoft v1.02 or v1.03"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 9C 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 [3] 2E [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
		$a0 at pe.entry_point
}
