rule SUSP_LNK_lnkfileoverRFC
{
	meta:
		description = "Detects APT lnk files that run double extraction and launch routines with autoruns"
		author = "@Grotezinfosec, modified by Florian Roth"
		date = "2018-09-18"
		os = "windows"
		filetype = "executable"

	strings:
		$command = "C:\\Windows\\System32\\cmd.exe" fullword ascii
		$command2 = {2F 00 63 00 20 00 66 00 69 00 6E 00 64 00 73 00 74 00 72}
		$base64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD" ascii
		$cert = " -decode " ascii

	condition:
		uint16(0)==0x004c and uint32(4)==0x00021401 and filesize >15KB and (2 of them )
}
