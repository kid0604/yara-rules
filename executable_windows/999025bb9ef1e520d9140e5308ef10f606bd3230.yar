import "pe"

rule Packman0001Bubbasoft
{
	meta:
		author = "malware-lu"
		description = "Detects Bubbasoft packman malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 0F 85 ?? FF FF FF 8D B3 [4] EB 3D 8B 46 0C 03 C3 50 FF 55 00 56 8B 36 0B F6 75 02 8B F7 03 F3 03 FB EB 1B D1 C1 D1 E9 73 05 0F B7 C9 EB 05 03 CB 8D 49 02 50 51 50 FF 55 04 AB 58 83 C6 04 8B 0E 85 C9 75 DF 5E 83 C6 14 8B 7E 10 85 FF 75 BC 8D 8B 00 }

	condition:
		$a0
}
