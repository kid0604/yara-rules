import "pe"

rule ExeSafeguardv10simonzh
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect ExeSafeguardv10simonzh malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { C0 5D EB 4E EB 47 DF 69 4E 58 DF 59 74 F3 EB 01 DF 75 EE 9A 59 9C 81 C1 E2 FF FF FF EB 01 DF 9D FF E1 E8 51 E8 EB FF FF FF DF 22 3F 9A C0 81 ED 19 18 40 00 EB 48 EB 47 DF 69 4E 58 DF 59 79 EE EB 01 DF 78 E9 DF 59 9C 81 C1 E5 FF FF FF 9D FF E1 EB 51 E8 EE }

	condition:
		$a0
}
