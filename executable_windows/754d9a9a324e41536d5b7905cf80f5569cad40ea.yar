rule INDICATOR_TOOL_PWS_SecurityXploded_EmailPasswordDumper
{
	meta:
		author = "ditekSHen"
		description = "Detects SecurityXploded Email Password Dumper tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\projects\\windows\\EmailPasswordDump\\Release\\FireMaster.pdb" ascii
		$s2 = "//Dump all the Email passwords to a file \"c:\\passlist.txt\"" ascii
		$s3 = "EmailPasswordDump" fullword wide
		$s4 = "//Dump all the Email passwords to console" ascii
		$s5 = "Email Password Dump" fullword wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
