import "pe"

rule VxDoom666
{
	meta:
		author = "malware-lu"
		description = "Detects the VxDoom666 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [3] 5E 83 EE ?? B8 CF 7B CD 21 3D CF 7B [2] 0E 1F 81 C6 [2] BF [2] B9 [2] FC F3 A4 06 1F 06 B8 [2] 50 CB B4 48 BB 2C 00 CD 21 }

	condition:
		$a0 at pe.entry_point
}
