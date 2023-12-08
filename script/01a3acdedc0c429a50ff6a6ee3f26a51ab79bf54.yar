rule INDICATOR_TOOL_DontSleep
{
	meta:
		author = "ditekShen"
		description = "Detects Keep Host Unlocked (Don't Sleep)"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = ":Repeat###DEL \"%s\"###if exist \"%s\" goto Repeat###DEL \"%s\"###" wide
		$s2 = "powrprof.dll,SetSuspendState" wide
		$s3 = "_selfdestruct.bat" wide
		$s4 = "please_sleep_block_" ascii
		$s5 = "Browser-Type: MiniBowserOK" wide
		$s6 = "m_use_all_rule_no_sleep" ascii
		$s7 = "BlockbyExecutionState: %d on:%d by_enable:%d" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
