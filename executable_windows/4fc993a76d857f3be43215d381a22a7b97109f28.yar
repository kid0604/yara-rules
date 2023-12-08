import "pe"

rule PEQuake006forgat
{
	meta:
		author = "malware-lu"
		description = "Detects the PEQuake variant 006 forgat"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 A5 00 00 00 2D [2] 00 00 00 00 00 00 00 00 00 3D [2] 00 2D [2] 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A [2] 00 5B [2] 00 6E [2] 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 64 72 65 73 73 00 00 00 47 65 74 4D 6F 64 75 6C 65 48 61 6E 64 6C 65 41 00 00 00 4C 6F 61 64 4C 69 62 72 61 72 79 41 00 [2] 00 00 56 69 72 74 75 61 6C 41 6C 6C 6F 63 00 00 00 00 00 00 }

	condition:
		$a0
}
