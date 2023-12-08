import "pe"

rule ThemidaWinLicenseV1000V1800OreansTechnologies
{
	meta:
		author = "malware-lu"
		description = "Detects Themida WinLicense version 1.0.0.0 - 1.8.0.0 by Oreans Technologies"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { B8 00 00 00 00 60 0B C0 74 58 E8 00 00 00 00 58 05 ?? 00 00 00 80 38 E9 75 ?? 61 EB ?? E8 00 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
