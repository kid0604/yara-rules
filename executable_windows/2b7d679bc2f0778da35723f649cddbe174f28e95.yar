rule PolishBankRAT_fdsvc_xor_loop
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Finds the custom xor decode loop for <PolishBankRAT_fdsvc>"
		os = "windows"
		filetype = "executable"

	strings:
		$loop = {0F B6 42 FF 48 8D 52 FF 30 42 01 FF CF 75 F1}

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $loop
}
