import "pe"

rule DropperCreatorV01Conflict
{
	meta:
		author = "malware-lu"
		description = "Detects a specific dropper creator pattern"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 00 00 00 00 5D 8D 05 [4] 29 C5 8D 85 [4] 31 C0 64 03 40 30 78 0C 8B 40 0C 8B 70 1C AD 8B 40 08 EB 09 }

	condition:
		$a0
}
