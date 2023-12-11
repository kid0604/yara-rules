import "pe"

rule PEArmor046ChinaCrackingGroup
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern used by the China Cracking Group in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 AA 00 00 00 2D [2] 00 00 00 00 00 00 00 00 00 3D [2] 00 2D [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B [2] 00 5C [2] 00 6F [2] 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 }

	condition:
		$a0 at pe.entry_point
}
