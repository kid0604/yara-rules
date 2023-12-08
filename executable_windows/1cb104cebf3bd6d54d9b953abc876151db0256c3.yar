import "pe"

rule ThinstallEmbedded24222428Jitit
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall embedded Jitit malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D 9B 1A 00 00 B9 84 1A 00 00 BA 14 1B 00 00 BE 00 10 00 00 BF B0 53 00 00 BD E0 1A 00 00 03 E8 81 75 00 [4] 81 75 04 [4] 81 75 08 [4] 81 75 0C [4] 81 75 10 }

	condition:
		$a0 at pe.entry_point
}
