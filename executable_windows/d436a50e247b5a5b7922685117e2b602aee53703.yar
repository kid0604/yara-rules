import "pe"

rule LauncherGeneratorv103
{
	meta:
		author = "malware-lu"
		description = "Detects LauncherGeneratorv103 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 68 00 20 40 00 68 10 20 40 00 6A 00 6A 00 6A 20 6A 00 6A 00 6A 00 68 F0 22 40 00 6A 00 E8 93 00 00 00 85 C0 0F 84 7E 00 00 00 B8 00 00 00 00 3B 05 68 20 40 00 74 13 6A ?? 68 60 23 40 00 68 20 23 40 00 6A 00 E8 83 00 00 00 A1 58 20 40 00 3B 05 6C 20 40 00 }

	condition:
		$a0
}
