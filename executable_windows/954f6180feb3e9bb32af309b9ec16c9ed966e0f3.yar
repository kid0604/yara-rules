rule Lazarus_BILDINGCAN_RC4
{
	meta:
		description = "BILDINGCAN_RC4 in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "8db272ea1100996a8a0ed0da304610964dc8ca576aa114391d1be9d4c5dab02e"
		os = "windows"
		filetype = "executable"

	strings:
		$customrc4 = { 75 C0 41 8B D2 41 BB 00 0C 00 00 0F 1F 80 00 00 00 00 }
		$id = "T1B7D95256A2001E" ascii
		$nop = { 66 66 66 66 0F 1F 84 00 00 00 00 }
		$post = "id=%s%s&%s=%s&%s=%s&%s=" ascii
		$command = "%s%sc \"%s > %s 2>&1" ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}
