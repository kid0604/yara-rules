import "pe"

rule VProtectorV10Build20041213testvcasm
{
	meta:
		author = "malware-lu"
		description = "Detects VProtector V1.0 Build 20041213 testvcasm malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC 6A FF 68 1A 89 40 00 68 56 89 40 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 C7 84 00 58 EB 01 E9 83 C0 07 50 }

	condition:
		$a0 at pe.entry_point
}
