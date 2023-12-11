rule INDICATOR_TOOL_PWS_LSASS_CreateMiniDump
{
	meta:
		author = "ditekSHen"
		description = "Detects CreateMiniDump tool"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "lsass.dmp" fullword wide
		$s2 = "lsass dumped successfully!" ascii
		$s3 = "Got lsass.exe PID:" ascii
		$s4 = "\\experiments\\CreateMiniDump\\CreateMiniDump\\" ascii
		$s5 = "MiniDumpWriteDump" fullword ascii

	condition:
		uint16(0)==0x5a4d and 2 of them
}
