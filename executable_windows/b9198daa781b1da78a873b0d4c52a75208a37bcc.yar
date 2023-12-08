rule INDICATOR_TOOL_PWS_SecurityXploded_FTPPasswordDumper
{
	meta:
		author = "ditekSHen"
		description = "Detects SecurityXploded FTP Password Dumper tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\projects\\windows\\FTPPasswordDump\\Release\\FireMaster.pdb" ascii
		$s2 = "//Dump all the FTP passwords to a file \"c:\\passlist.txt\"" ascii
		$s3 = "//Dump all the FTP passwords to console" ascii
		$s4 = "FTP Password Dump" fullword wide

	condition:
		uint16(0)==0x5a4d and 3 of them
}
