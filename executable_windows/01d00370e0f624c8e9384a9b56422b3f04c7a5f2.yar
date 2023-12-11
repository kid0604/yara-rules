rule Codoso_CustomTCP_4
{
	meta:
		description = "Detects Codoso APT CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash1 = "ea67d76e9d2e9ce3a8e5f80ff9be8f17b2cd5b1212153fdf36833497d9c060c0"
		hash2 = "130abb54112dd47284fdb169ff276f61f2b69d80ac0a9eac52200506f147b5f8"
		hash3 = "3ea6b2b51050fe7c07e2cf9fa232de6a602aa5eff66a2e997b25785f7cf50daa"
		hash4 = "02cf5c244aebaca6195f45029c1e37b22495609be7bdfcfcd79b0c91eac44a13"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "varus_service_x86.dll" fullword ascii
		$s1 = "/s %s /p %d /st %d /rt %d" fullword ascii
		$s2 = "net start %%1" fullword ascii
		$s3 = "ping 127.1 > nul" fullword ascii
		$s4 = "McInitMISPAlertEx" fullword ascii
		$s5 = "sc start %%1" fullword ascii
		$s6 = "net stop %%1" fullword ascii
		$s7 = "WorkerRun" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <400KB and 5 of them ) or ($x1 and 2 of ($s*))
}
