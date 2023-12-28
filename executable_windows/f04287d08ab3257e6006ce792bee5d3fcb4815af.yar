rule lazarus_dbgsymbols_str
{
	meta:
		description = "Exploit tools in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash = "50869d2a713acf406e160d6cde3b442fafe7cfe1221f936f3f28c4b9650a66e9"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "getsymbol" nocase
		$str2 = "dbgsymbol.com" wide
		$str3 = "c:\\symbols" wide
		$str4 = "symchk.exe /r /if %s /s SRV*%s*%s" wide
		$str5 = "Symbol Download Finished!" wide
		$filename = "symbolcheck.dll" wide

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and 3 of ($str*) and all of ($filename)
}
