rule Codoso_CustomTCP_2
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "3577845d71ae995762d4a8f43b21ada49d809f95c127b770aff00ae0b64264a3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "varus_service_x86.dll" fullword ascii
		$s2 = "/s %s /p %d /st %d /rt %d" fullword ascii
		$s3 = "net start %%1" fullword ascii
		$s4 = "ping 127.1 > nul" fullword ascii
		$s5 = "McInitMISPAlertEx" fullword ascii
		$s6 = "sc start %%1" fullword ascii
		$s7 = "B_WKNDNSK^" fullword ascii
		$s8 = "net stop %%1" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <406KB and all of them
}
