rule malware_sqroot_coreloader
{
	meta:
		description = "loader downloaded by sqroot"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$query = "%s?hid=%s&uid=%s&cid=%x" ascii
		$decode_routine = {8A 8A ?? ?? ?? ?? 02 C1 32 C1 2A C1 0F B6 8E ?? ?? ?? ?? 88 86 ?? ?? ?? ?? 8D 46 ?? 99 F7 FF 8A 82 ?? ?? ?? ?? 02 C8 32 C8 2A C8 88 8E ?? ?? ?? ?? 83 C6 02 81 FE 0A 04 00 00}

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and all of them
}
