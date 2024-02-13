rule malware_sqroot_keylogger
{
	meta:
		description = "keylog plugin downloaded by sqroot"
		author = "JPCERT/CC Incident Response Group"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "record-%04d%02d%02d-%02d%02d%02d.ini" ascii
		$s2 = "g_hKeyLogMsgLoopThread exit" ascii
		$s3 = "OCR_INI_DEBUG.abc" ascii
		$s4 = {59 6F 75 27 72 65 20 61  63 74 69 76 61 74 65 64 00 00 00 00 52 33 32 41 63 74 69 76 65}

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 2 of them
}
