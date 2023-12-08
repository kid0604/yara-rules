rule INDICATOR_TOOL_PWS_Fgdump
{
	meta:
		author = "ditekSHen"
		description = "detects all versions of the password dumping tool, fgdump. Observed to be used by DustSquad group."
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "dumping server %s" ascii
		$s2 = "dump on server %s" ascii
		$s3 = "dump passwords: %s" ascii
		$s4 = "Dumping cache" nocase ascii
		$s5 = "SECURITY\\Cache" ascii
		$s6 = "LSASS.EXE process" ascii
		$s7 = " AntiVirus " nocase ascii
		$s8 = " IPC$ " ascii
		$s9 = "Exec failed, GetLastError returned %d" fullword ascii
		$10 = "writable connection to %s" ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
