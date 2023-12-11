import "pe"

rule Thinstall24x25xJititSoftware
{
	meta:
		author = "malware-lu"
		description = "Detects Thinstall 24x25x Jitit Software malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 55 8B EC B8 [4] BB [4] 50 E8 00 00 00 00 58 2D [4] B9 [4] BA [4] BE [4] BF [4] BD [4] 03 E8 }

	condition:
		$a0 at pe.entry_point
}
