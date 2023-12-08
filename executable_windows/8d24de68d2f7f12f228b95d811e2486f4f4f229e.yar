import "pe"

rule HASPHLProtectionV1XAladdin
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of HASP HL protection in Aladdin software"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 53 56 57 60 8B C4 A3 [4] B8 [4] 2B 05 [4] A3 [4] 83 3D [4] 00 74 15 8B 0D [4] 51 FF 15 [4] 83 C4 04 E9 A5 00 00 00 68 [4] FF 15 [4] A3 [4] 68 [4] FF 15 }
		$a1 = { 55 8B EC 53 56 57 60 8B C4 A3 [4] B8 [4] 2B 05 [4] A3 [4] 83 3D [4] 00 74 15 8B 0D [4] 51 FF 15 [4] 83 C4 04 E9 A5 00 00 00 68 [4] FF 15 [4] A3 [4] 68 [4] FF 15 [4] A3 [4] 8B 15 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
