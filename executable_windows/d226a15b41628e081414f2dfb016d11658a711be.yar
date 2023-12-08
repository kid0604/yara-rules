import "pe"

rule SPLayerv008
{
	meta:
		author = "malware-lu"
		description = "Detects SPLayer version 008"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8D 40 00 B9 [4] 6A ?? 58 C0 0C [2] 48 [2] 66 13 F0 91 3B D9 [8] 00 00 00 00 }

	condition:
		$a0
}
