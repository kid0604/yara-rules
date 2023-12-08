import "pe"

rule PEiDBundlev102v104BoBBobSoft
{
	meta:
		author = "malware-lu"
		description = "Detects PE files that are packed with the BoBBobSoft v1.02-v1.04 packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 36 [3] 2E [3] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 80 00 00 00 00 4B 65 72 6E 65 6C 33 32 2E 44 }

	condition:
		$a0 at pe.entry_point
}
