import "pe"

rule MALWARE_Win_AgentTeslaV2
{
	meta:
		author = "ditekSHen"
		description = "AgenetTesla Type 2 Keylogger payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "get_kbHook" ascii
		$s2 = "GetPrivateProfileString" ascii
		$s3 = "get_OSFullName" ascii
		$s4 = "get_PasswordHash" ascii
		$s5 = "remove_Key" ascii
		$s6 = "FtpWebRequest" ascii
		$s7 = "logins" fullword wide
		$s8 = "keylog" fullword wide
		$s9 = "1.85 (Hash, version 2, native byte-order)" wide
		$cl1 = "Postbox" fullword ascii
		$cl2 = "BlackHawk" fullword ascii
		$cl3 = "WaterFox" fullword ascii
		$cl4 = "CyberFox" fullword ascii
		$cl5 = "IceDragon" fullword ascii
		$cl6 = "Thunderbird" fullword ascii

	condition:
		( uint16(0)==0x5a4d and 6 of ($s*)) or (6 of ($s*) and 2 of ($cl*))
}
