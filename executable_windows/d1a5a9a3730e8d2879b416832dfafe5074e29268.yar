import "pe"

rule bambam001bedrock
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of a specific pattern at the entry point of a PE file, which may indicate the presence of the Bambam001bedrock malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A 14 E8 9A 05 00 00 8B D8 53 68 [4] E8 6C FD FF FF B9 05 00 00 00 8B F3 BF [4] 53 F3 A5 E8 8D 05 00 00 8B 3D [4] A1 [4] 66 8B 15 [4] B9 [4] 2B CF 89 45 E8 89 0D [4] 66 89 55 EC 8B 41 3C 33 D2 03 C1 83 C4 10 66 8B 48 06 66 8B 50 14 81 E1 FF FF 00 00 8D 5C 02 18 8D 41 FF 85 C0 }

	condition:
		$a0 at pe.entry_point
}
