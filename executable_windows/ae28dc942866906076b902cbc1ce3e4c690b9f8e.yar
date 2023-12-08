import "pe"

rule yzpack112UsAr
{
	meta:
		author = "malware-lu"
		description = "Detects a specific packer used by malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 5A 52 45 60 83 EC 18 8B EC 8B FC 33 C0 64 8B 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 8B 40 34 83 C0 7C 8B 40 3C AB E9 [4] B4 09 BA 00 00 1F CD 21 B8 01 4C CD 21 40 00 00 00 50 45 00 00 4C 01 02 00 [4] 00 00 00 00 00 00 00 00 E0 00 [2] 0B 01 [4] 00 00 }

	condition:
		$a0 at pe.entry_point
}
