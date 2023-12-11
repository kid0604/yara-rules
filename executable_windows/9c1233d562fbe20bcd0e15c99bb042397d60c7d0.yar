import "pe"

rule ThemidaWinLicenseV18XV19XOreansTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects Themida WinLicense versions 18.x and 19.x by Oreans Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 [4] 60 0B C0 74 68 E8 00 00 00 00 58 05 53 00 00 00 80 38 E9 75 13 61 EB 45 DB 2D [4] FF FF FF FF FF FF FF FF 3D [4] 00 00 58 25 00 F0 FF FF 33 FF 66 BB [2] 66 83 [2] 66 39 18 75 12 0F B7 50 3C 03 D0 BB [4] 83 C3 ?? 39 1A 74 07 2D [4] EB DA 8B F8 B8 [4] 03 C7 B9 [4] 03 CF EB 0A B8 [4] B9 [4] 50 51 E8 [4] E8 [4] 58 2D [4] B9 [4] C6 00 E9 83 E9 05 89 48 01 61 E9 }

	condition:
		$a0 at pe.entry_point
}
