import "pe"

rule PrivateEXEv20a
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of a specific private executable file version 20a"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 53 E8 00 00 00 00 5B 8B C3 2D }
		$a1 = { 06 60 C8 [3] 0E 68 [2] 9A [4] 3D [2] 0F [3] 50 50 0E 68 [2] 9A [4] 0E }
		$a2 = { 53 E8 [4] 5B 8B C3 2D [4] 50 81 [5] 8B }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point or $a2 at pe.entry_point
}
