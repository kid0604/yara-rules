rule INDICATOR_TOOL_BURTNCIGAR
{
	meta:
		author = "ditekSHen"
		description = "Detects BURNTCIGAR a utility which terminates processes associated with endpoint security software"
		clamav1 = "INDICATOR.Win.TOOL.BURNTCIGAR"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Kill PID =" ascii
		$s2 = "CreateFile Error =" ascii
		$s3 = "\\KillAV" ascii
		$s4 = "DeviceIoControl" ascii

	condition:
		uint16(0)==0x5a4d and 3 of them
}
