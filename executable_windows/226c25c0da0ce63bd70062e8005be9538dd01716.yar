rule INDICATOR_TOOL_GoGoProcDump
{
	meta:
		author = "ditekSHen"
		description = "Detects GoGo (lsass) process dump tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "C:\\temp" ascii
		$s2 = "gogo" fullword ascii
		$s3 = "/DumpLsass-master/SilentProcessExit/" ascii
		$s4 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Time Zone" ascii
		$s5 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\lsass.exe" ascii
		$s6 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\lsass.exe" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
