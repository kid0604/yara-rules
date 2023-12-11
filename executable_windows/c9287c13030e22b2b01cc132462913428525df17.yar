import "pe"

rule KeyBoy_876_0x4e20000
{
	meta:
		description = "Detects KeyBoy Backdoor"
		author = "Markus Neis, Florian Roth"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
		date = "2018-03-26"
		hash1 = "6e900e5b6dc4f21a004c5b5908c81f055db0d7026b3c5e105708586f85d3e334"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "%s\\rundll32.exe %s ServiceTake %s %s" fullword ascii
		$x2 = "#%sCmd shell is not running,or your cmd is error!" fullword ascii
		$x3 = "Take Screen Error,May no user login!" fullword ascii
		$x4 = "Get logon user fail!" fullword ascii
		$x5 = "8. LoginPasswd:%s" fullword ascii
		$x6 = "Take Screen Error,service dll not exists" fullword ascii
		$s1 = "taskkill /f /pid %s" fullword ascii
		$s2 = "TClient.exe" fullword ascii
		$s3 = "%s\\wab32res.dll" fullword ascii
		$s4 = "%s\\rasauto.dll" fullword ascii
		$s5 = "Download file:%s index:%d" fullword ascii
		$s6 = "LogonUser: [%s]" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and (1 of ($x*) or 3 of them )
}
