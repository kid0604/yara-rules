import "pe"

rule MALWARE_Win_TJKeylogger
{
	meta:
		author = "ditekSHen"
		description = "TJKeylogger payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "TJKeyLogger" fullword ascii
		$s2 = "software\\microsoft\\windows\\currentversion\\run" fullword ascii
		$s3 = "\\Passwords.txt" ascii
		$s4 = "TJKeyLogItem" fullword ascii
		$s5 = "TJKeyAsyncLog" fullword ascii
		$s6 = "FM_GETDSKLST" fullword ascii
		$s7 = "KL_GETMODE" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
