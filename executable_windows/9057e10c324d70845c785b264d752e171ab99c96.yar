rule INDICATOR_TOOL_PWS_LSASS_NanoDump
{
	meta:
		author = "ditekSHen"
		description = "Detects NanoDump tool that creates a minidump of the LSASS process"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Registry\\Machine\\Software\\Microsoft\\Windows\\Windows Error Reporting\\LocalDumps\\" fullword wide
		$s2 = "\\Registry\\Machine\\Software\\Microsoft\\Windows NT\\CurrentVersion\\SilentProcessExit\\" fullword wide
		$s3 = "DumpType" fullword wide
		$s4 = "LocalDumpFolder" fullword wide
		$s5 = "\\??\\C:\\Windows\\System32\\seclogon.dll" fullword wide
		$s6 = "minidump %s" ascii
		$s7 = "--seclogon-" ascii
		$s8 = "shtinkering" ascii
		$s9 = "LSASS PID: %ld" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
