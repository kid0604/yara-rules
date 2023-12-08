import "pe"

rule BamBamv001Bedrock
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of BamBamv001Bedrock malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 FB [2] 00 E8 6C FD FF FF B9 05 00 00 00 8B F3 BF FB [2] 00 53 F3 A5 E8 8D 05 00 00 8B 3D 03 [2] 00 A1 2B [2] 00 66 8B 15 2F [2] 00 B9 80 [2] 00 2B CF 89 45 E8 89 0D 6B [2] 00 66 89 55 EC 8B 41 3C 33 D2 03 C1 }

	condition:
		$a0
}
