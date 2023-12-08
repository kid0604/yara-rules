import "pe"

rule InstallShieldCustom
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of InstallShield custom action code in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 83 EC 44 56 FF 15 [2] 41 00 8B F0 85 F6 75 08 6A FF FF 15 [2] 41 00 8A 06 57 8B 3D [2] 41 00 3C 22 75 1B 56 FF D7 8B F0 8A 06 3C 22 74 04 84 C0 75 F1 80 3E 22 75 15 56 FF D7 8B }

	condition:
		$a0 at pe.entry_point
}
