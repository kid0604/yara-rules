import "pe"

rule ThinstallVirtualizationSuite30XThinstallCompany
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall Virtualization Suite 3.0 by Thinstall Company"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 9C 60 68 [4] 68 [4] E8 00 00 00 00 58 BB [4] 2B C3 50 68 [4] 68 [4] 68 [4] E8 BA FE FF FF E9 [4] CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA }
		$a1 = { 9C 60 68 [4] 68 [4] E8 00 00 00 00 58 BB [4] 2B C3 50 68 [4] 68 [4] 68 [4] E8 BA FE FF FF E9 [4] CC CC CC CC CC CC CC 55 8B EC 83 C4 F4 FC 53 57 56 8B 75 08 8B 7D 0C C7 45 FC 08 00 00 00 33 DB BA [4] 43 33 C0 E8 19 01 00 00 73 0E 8B 4D F8 E8 27 01 00 00 02 45 F7 AA EB E9 E8 04 01 00 00 0F 82 96 00 00 00 E8 F9 00 00 00 73 5B B9 04 00 00 00 E8 05 01 00 00 48 74 DE 0F 89 [4] E8 DF 00 00 00 73 1B 55 BD [4] E8 DF 00 00 00 88 07 47 4D 75 F5 E8 C7 00 00 00 72 E9 5D EB }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
