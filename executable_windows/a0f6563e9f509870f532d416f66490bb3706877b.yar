rule Andromeda_alt_2
{
	meta:
		description = "This Role Detects Andromeda  Malware"
		Data = "25/10/2023"
		Author = "@FarghlyMal"
		os = "windows"
		filetype = "executable"

	strings:
		$HexStream = {3D 07 FD E5 4C [3-7]          // this opcodes for some values of hashes used in ANTI-ANALYSIS
            3D 6C 32 81 81 [3-7]
            3D AF 33 E2 31 [3-7]
            3D F6 7D D4 91 [3-7]
            3D 54 DC CD E8 [3-7]
            3D 6C 6D 8C 00 [3-7] 
            3D 0E BA D0 A8 [3-7] 
            3D 0E 3C EF A4 [3-7] 
            3D 5E BA D7 5C}
		$HexStream2 = {68 6E 75 6D 00 
                68 73 6B 5C 65 
                68 73 5C 64 69
                68 76 69 63 65
                68 5C 73 65 72
                68 6C 73 65 74
                68 6E 74 72 6F
                68 6E 74 63 6F}

	condition:
		uint16(0)==0x5A4D and all of ($HexStream*) and filesize <17KB and filesize >10KB
}
