import "pe"

rule UPX290LZMAMarkusOberhumerLaszloMolnarJohnReiser
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting UPX compressed files with LZMA compression"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 83 CD FF 89 E5 8D 9C 24 [4] 31 C0 50 39 DC 75 FB 46 46 53 68 [4] 57 83 C3 04 53 68 [4] 56 83 C3 04 53 50 C7 03 [4] 90 90 }
		$a1 = { 60 BE [4] 8D BE [4] 57 83 CD FF EB 10 90 90 90 90 90 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 8B 1E 83 EE FC 11 DB 11 C0 01 DB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
