rule malware_sqroot_corerat
{
	meta:
		description = "RAT downloaded by sqroot"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "openfile %s error!" ascii
		$a2 = "remote file error!" ascii
		$a3 = "upload well!" ascii
		$a4 = "%s?hid=%s&uid=%s&cid=%x" ascii
		$a5 = "%s|%s|%s|%s|%s|%s|%d|%s|" ascii
		$b1 = {68 24 11 00 00 E8}
		$b2 = {C7 03 37 11 00 00}

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and ( all of ($a*) or all of ($b*))
}
