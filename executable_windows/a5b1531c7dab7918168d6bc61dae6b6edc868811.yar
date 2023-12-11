import "pe"

rule SmartEMicrosoft
{
	meta:
		author = "malware-lu"
		description = "Detects SmartE malware targeting Microsoft Windows"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 15 03 00 00 00 ?? 00 00 00 00 00 00 00 00 00 00 00 68 00 00 00 00 55 E8 00 00 00 00 5D 81 ED 1D 00 00 00 8B C5 55 60 9C 2B 85 8F 07 00 00 89 85 83 07 00 00 FF 74 24 2C E8 BB 01 00 00 0F 82 2F 06 00 00 E8 8E 04 00 00 49 0F 88 23 06 }

	condition:
		$a0 at pe.entry_point
}
