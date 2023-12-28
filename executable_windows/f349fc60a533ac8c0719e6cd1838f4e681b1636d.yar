rule BlackTech_BTSDoor_str
{
	meta:
		description = "BTSDoor in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "85fa7670bb2f4ef3ca688d09edfa6060673926edb3d2d21dff86c664823dd609"
		hash = "ee6ed35568c43fbb5fd510bc863742216bba54146c6ab5f17d9bfd6eacd0f796"
		os = "windows"
		filetype = "executable"

	strings:
		$data1 = "Not implemented!" ascii wide
		$data2 = "Win%d.%d.%d" ascii wide
		$data3 = "CMD Error!" ascii wide
		$data4 = { 76 45 8B 9E 6F 00 00 00 45 76 8B 9E 6F 00 00 00 }
		$pdb1 = "C:\\Users\\Tsai\\Desktop\\20180522windows_tro\\BTSWindows\\Serverx86.pdb" ascii
		$pdb2 = "\\BTSWindows\\Serverx86.pdb" ascii
		$pdb3 = "\\BTSWindows\\Serverx64.pdb" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and (1 of ($pdb*) or 4 of ($data*))
}
