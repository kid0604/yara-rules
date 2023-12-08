rule PolishBankRAT_srservice_xorloop
{
	meta:
		author = "Booz Allen Hamilton Dark Labs"
		description = "Finds the custom xor decode loop for <PolishBankRAT_srservice>"
		os = "windows"
		filetype = "executable"

	strings:
		$loop = { 48 8B CD E8 60 FF FF FF 48 FF C3 32 44 1E FF 48 FF CF 88 43 FF }

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and $loop
}
