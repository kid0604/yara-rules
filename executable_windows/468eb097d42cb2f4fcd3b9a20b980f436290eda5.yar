import "pe"

rule MorphineV27Holy_FatherRatter29A
{
	meta:
		author = "malware-lu"
		description = "Detects the MorphineV27Holy_FatherRatter29A malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 [8] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 [8] 00 00 00 00 [8] 00 00 00 00 4B 65 52 6E 45 6C 33 32 2E 64 4C 6C 00 00 47 65 74 50 72 6F 63 41 64 64 72 }

	condition:
		$a0
}
