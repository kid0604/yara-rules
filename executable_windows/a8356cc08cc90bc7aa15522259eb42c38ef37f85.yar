import "pe"

rule VMProtect106107PolyTech
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of VMProtect version 1.06-1.07 with PolyTech"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 68 00 00 00 00 8B 74 24 28 BF [4] FC 89 F3 03 34 24 AC 00 D8 }

	condition:
		$a0
}
