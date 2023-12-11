import "pe"

rule PEQuakev006byfORGAT
{
	meta:
		author = "malware-lu"
		description = "Detects the Quake v0.06 malware by f0rgat"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 A5 00 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 3D ?? 00 00 2D ?? 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 4A ?? 00 00 5B ?? 00 00 6E ?? 00 00 00 00 00 00 6B 45 72 4E 65 4C 33 32 2E 64 4C 6C 00 00 00 47 65 74 50 72 6F 63 41 64 }

	condition:
		$a0
}
