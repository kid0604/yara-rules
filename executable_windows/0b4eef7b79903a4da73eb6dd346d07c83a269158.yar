import "pe"

rule FixupPakv120
{
	meta:
		author = "malware-lu"
		description = "Yara rule to detect FixupPakv120 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 E8 00 00 00 00 5D 81 ED [2] 00 00 BE 00 ?? 00 00 03 F5 BA 00 00 [2] 2B D5 8B DD 33 C0 AC 3C 00 74 3D 3C 01 74 0E 3C 02 74 0E 3C 03 74 0D 03 D8 29 13 EB E7 66 AD EB F6 AD EB F3 AC 0F B6 C8 3C 00 74 06 3C 01 74 09 EB 0A 66 AD 0F B7 C8 EB 03 AD 8B C8 }

	condition:
		$a0 at pe.entry_point
}
