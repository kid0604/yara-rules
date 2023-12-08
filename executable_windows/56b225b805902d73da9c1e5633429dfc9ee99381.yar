import "pe"

rule UPX293300LZMAMarkusOberhumerLaszloMolnarJohnReiser
{
	meta:
		author = "malware-lu"
		description = "Detects UPX compressed files with specific entry point code"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 BE [4] 8D BE [4] 57 89 E5 8D 9C 24 [4] 31 C0 50 39 DC 75 FB 46 46 53 68 [4] 57 83 C3 04 53 68 [4] 56 83 C3 04 53 50 C7 03 03 00 02 00 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
