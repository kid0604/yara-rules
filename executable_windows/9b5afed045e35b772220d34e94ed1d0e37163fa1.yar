rule INDICATOR_TOOL_PWS_SecurityXploded_BrowserPasswordDumper
{
	meta:
		author = "ditekSHen"
		description = "Detects SecurityXploded Browser Password Dumper tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\projects\\windows\\BrowserPasswordDump\\Release\\FireMaster.pdb" ascii
		$s2 = "%s: Dumping passwords" fullword ascii
		$s3 = "%s - Found login data file...dumping the passwords from file %s" fullword ascii
		$s4 = "%s Dumping secrets from login json file %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}
