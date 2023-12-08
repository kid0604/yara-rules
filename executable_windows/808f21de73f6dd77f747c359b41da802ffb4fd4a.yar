rule INDICATOR_TOOL_PWS_PwDump7
{
	meta:
		author = "ditekSHen"
		description = "Detects Pwdump7 password Dumper"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "savedump.dat" fullword ascii
		$s2 = "Asd -_- _RegEnumKey fail!" fullword ascii
		$s3 = "\\SAM\\" ascii
		$s4 = "Unable to dump file %S" fullword ascii
		$s5 = "NO PASSWORD" ascii

	condition:
		( uint16(0)==0x5a4d and 4 of them ) or ( all of them )
}
