rule Lazarus_BILDINGCAN_module
{
	meta:
		description = "BILDINGCAN_AES module in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$cmdcheck1 = { 3D ED AB 00 00 0F ?? ?? ?? 00 00 3D EF AB 00 00 0F ?? ?? ?? 00 00 3D 17 AC 00 00 0F ?? ?? ?? 00 00 }
		$cmdcheck2 = { 3D 17 AC 00 00 0F ?? ?? ?? 00 00 3D 67 EA 00 00 0F ?? ?? ?? 00 00 }
		$recvsize = { 00 00 41 81 F8 D8 AA 02 00 }
		$nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
		$rand = { 69 D2 ?? ?? 00 00 2B ?? 81 C? D2 04 00 00 }

	condition:
		uint16(0)==0x5a4d and 3 of them
}
