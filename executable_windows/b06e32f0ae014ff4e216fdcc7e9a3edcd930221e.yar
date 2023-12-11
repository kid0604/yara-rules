rule Makop_Ransomware
{
	meta:
		description = "Detect the risk of Ransomware Makop Rule 4"
		hash1 = "082a2ce2dde8b3a50f2d499496879e85562ee949cb151c8052eaaa713cddd0f8"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "MPR.dll" fullword ascii
		$s2 = "-%08X" fullword ascii
		$api1 = {43 72 79 70 74 47 65 6E 52 61 6E 64 6F 6D 00 00 CA 00 43 72 79 70 74 49 6D 70 6F 72 74 4B 65 79 00 00 BA 00 43 72 79 70 74 45 6E 63 72 79 70 74}
		$api2 = {B7 00 43 72 79 70 74 44 65 73 74 72 6F 79 4B 65 79 00 B4 00 43 72 79 70 74 44 65 63 72 79 70 74 00 00 B1 00 43 72 79 70 74 41 63 71 75 69 72 65 43 6F 6E 74 65 78 74 57}
		$api3 = {10 00 57 4E 65 74 43 6C 6F 73 65 45 6E 75 6D 00 3D 00 57 4E 65 74 4F 70 65 6E 45 6E 75 6D 57 00 1C 00 57 4E 65 74 45 6E 75 6D 52 65 73 6F 75 72 63 65 57 00 4D 50 52 2E 64 6C 6C}

	condition:
		uint16(0)==0x5a4d and filesize <200KB and 3 of them
}
