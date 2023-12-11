rule INDICATOR_TOOL_PET_SharpHound
{
	meta:
		author = "ditekSHen"
		description = "Detects BloodHound"
		os = "windows"
		filetype = "script"

	strings:
		$id1 = "InvokeBloodHound" fullword ascii
		$id2 = "Sharphound" ascii nocase
		$s1 = "SamServerExecute" fullword ascii
		$s2 = "get_RemoteDesktopUsers" fullword ascii
		$s3 = "commandline.dll.compressed" ascii wide
		$s4 = "operatingsystemservicepack" fullword wide
		$s5 = "LDAP://" fullword wide
		$s6 = "wkui1_logon_domain" fullword ascii
		$s7 = "GpoProps" fullword ascii
		$s8 = "a517a8de-5834-411d-abda-2d0e1766539c" fullword ascii nocase

	condition:
		uint16(0)==0x5a4d and ( all of ($id*) or 6 of ($s*) or (1 of ($id*) and 4 of ($s*)))
}
