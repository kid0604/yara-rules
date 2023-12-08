import "pe"

rule dUP2diablo2oo2
{
	meta:
		author = "malware-lu"
		description = "Detects the dUP2diablo2oo2 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] E8 [4] 8B F0 6A 00 68 [4] 56 E8 [4] A2 [4] 6A 00 68 [4] 56 E8 [4] A2 [4] 6A 00 68 [4] 56 E8 [4] A2 [4] 68 [4] 68 [4] 56 E8 [4] 3C 01 75 19 BE [4] 68 00 02 00 00 56 68 }

	condition:
		$a0 at pe.entry_point
}
