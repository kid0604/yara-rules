rule dump_tool
{
	meta:
		author = "@patrickrolsen"
		reference = "Related to pwdump6 and fgdump tools"
		description = "Detects the presence of dump tools related to pwdump6 and fgdump"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "lsremora"
		$s2 = "servpw"
		$s3 = "failed: %d"
		$s4 = "fgdump"
		$s5 = "fgexec"
		$s6 = "fgexecpipe"

	condition:
		uint16(0)==0x5A4D and 3 of ($s*)
}
