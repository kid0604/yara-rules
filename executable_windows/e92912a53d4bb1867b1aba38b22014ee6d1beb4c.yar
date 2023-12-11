import "pe"

rule GameGuardnProtect
{
	meta:
		author = "malware-lu"
		description = "Yara rule for detecting GameGuardnProtect malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 31 FF 74 06 61 E9 4A 4D 50 30 5A BA 7D 00 00 00 80 7C 24 08 01 E9 00 00 00 00 60 BE [4] 31 FF 74 06 61 E9 4A 4D 50 30 8D BE [4] 31 C9 74 06 61 E9 4A 4D 50 30 B8 7D 00 00 00 39 C2 B8 4C 00 00 00 F7 D0 75 3F 64 A1 30 00 00 00 85 C0 78 23 8B 40 0C 8B 40 0C C7 40 20 00 10 00 00 64 A1 18 00 00 00 8B 40 30 0F B6 40 02 85 C0 75 16 E9 12 00 00 00 31 C0 64 A0 20 00 00 00 85 C0 75 05 E9 01 00 00 00 61 57 83 CD FF EB 0B 90 8A 06 46 88 07 47 01 DB 75 07 8B 1E 83 EE FC 11 DB 72 ED B8 01 00 00 00 01 DB 75 07 }

	condition:
		$a0 at pe.entry_point
}
