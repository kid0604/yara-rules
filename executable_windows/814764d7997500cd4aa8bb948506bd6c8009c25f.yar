import "pe"

rule LaunchAnywherev4001
{
	meta:
		author = "malware-lu"
		description = "Detects the LaunchAnywherev4001 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 89 E5 53 83 EC 48 55 B8 FF FF FF FF 50 50 68 E0 3E 42 00 64 FF 35 00 00 00 00 64 89 25 00 00 00 00 68 C0 69 44 00 E8 E4 80 FF FF 59 E8 4E 29 00 00 E8 C9 0D 00 00 85 C0 75 08 6A FF E8 6E 2B 00 00 59 E8 A8 2C 00 00 E8 23 2E 00 00 FF 15 4C C2 44 00 89 C3 }

	condition:
		$a0 at pe.entry_point
}
