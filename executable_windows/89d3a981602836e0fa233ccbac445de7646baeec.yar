import "pe"

rule PEArmor046Hying
{
	meta:
		author = "malware-lu"
		description = "Detects suspicious code injection in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 AA 00 00 00 2D [2] 00 00 00 00 00 00 00 00 00 3D [2] 00 2D [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4B [2] 00 5C [2] 00 6F [2] 00 00 00 00 00 4B 45 52 4E 45 4C 33 32 2E 64 6C 6C 00 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 }
		$a1 = { E8 AA 00 00 00 2D [3] 00 00 00 00 00 00 00 00 3D }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
