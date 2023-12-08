rule Malware_QA_not_copy
{
	meta:
		description = "VT Research QA uploaded malware - file not copy.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "VT Research QA"
		date = "2016-08-29"
		score = 80
		hash1 = "1410f38498567b64a4b984c69fe4f2859421e4ac598b9750d8f703f1d209f836"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "U2VydmVyLmV4ZQ==" fullword wide
		$x2 = "\\not copy\\obj\\Debug\\not copy.pdb" ascii
		$x3 = "fuckyou888.ddns.net" fullword wide
		$s1 = "cmd.exe /c ping 0 -n 2 & del \"" fullword wide
		$s2 = "Server.exe" fullword wide
		$s3 = "Execute ERROR" fullword wide
		$s4 = "not copy.exe" fullword wide
		$s5 = "Non HosT" fullword wide
		$s6 = "netsh firewall delete allowedprogram" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and (1 of ($x*) or 4 of ($s*))) or (5 of them )
}
