rule Dos_c_alt_1
{
	meta:
		description = "Chinese Hacktool Set - file c.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "3deb6bd52fdac6d5a3e9a91c585d67820ab4df78"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "!Win32 .EXE." fullword ascii
		$s1 = ".MPRESS1" fullword ascii
		$s2 = ".MPRESS2" fullword ascii
		$s3 = "XOLEHLP.dll" fullword ascii
		$s4 = "</body></html>" fullword ascii
		$s8 = "DtcGetTransactionManagerExA" fullword ascii
		$s9 = "GetUserNameA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
