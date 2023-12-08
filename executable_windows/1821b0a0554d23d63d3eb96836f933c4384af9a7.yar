import "pe"

rule ThemidaWinLicenseV1802OreansTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects Themida WinLicense V1802 by Oreans Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 68 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? DB 2D [4] FF FF FF FF FF FF FF FF 3D 40 E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
