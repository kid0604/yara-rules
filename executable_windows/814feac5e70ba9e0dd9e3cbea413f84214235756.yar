import "pe"

rule WiltedTulip_vminst
{
	meta:
		description = "Detects malware used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "930118fdf1e6fbffff579e65e1810c8d91d4067cbbce798c5401cf05d7b4c911"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\C++\\Trojan\\Target\\" ascii
		$s1 = "%s\\system32\\rundll32.exe" fullword wide
		$s2 = "$C:\\Windows\\temp\\l.tmp" fullword wide
		$s3 = "%s\\svchost.exe" fullword wide
		$s4 = "args[10] is %S and command is %S" fullword ascii
		$s5 = "LOGON USER FAILD " fullword ascii
		$s6 = "vminst.tmp" fullword wide
		$s7 = "operator co_await" fullword ascii
		$s8 = "?ReflectiveLoader@@YGKPAX@Z" fullword ascii
		$s9 = "%s -k %s" fullword wide
		$s10 = "ERROR in %S/%d" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <900KB and (1 of ($x*) or 5 of ($s*))
}
