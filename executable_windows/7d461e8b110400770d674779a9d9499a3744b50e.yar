import "pe"

rule PrincessSandyv10eMiNENCEProcessPatcherPatch
{
	meta:
		author = "malware-lu"
		description = "Detects PrincessSandyv10eMiNENCEProcessPatcherPatch malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 27 11 40 00 E8 3C 01 00 00 6A 00 E8 41 01 00 00 A3 00 20 40 00 8B 58 3C 03 D8 0F B7 43 14 0F B7 4B 06 8D 7C 18 18 81 3F 2E 4C 4F 41 74 0B 83 C7 28 49 75 F2 E9 A7 00 00 00 8B 5F 0C 03 1D 00 20 40 00 89 1D 04 20 40 00 8B FB 83 C7 04 68 4C 20 40 00 68 08 }

	condition:
		$a0
}
