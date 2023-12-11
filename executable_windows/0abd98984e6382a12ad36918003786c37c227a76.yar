import "pe"

rule MALWARE_Win_ClipBanker03
{
	meta:
		author = "ditekSHen"
		description = "Detects ClipBanker"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "UNIC_KEY" fullword wide
		$s2 = "[StartUp]" fullword wide
		$s3 = "[Kill]" fullword wide
		$s4 = "[antivm]" fullword wide
		$s5 = "AntiVM" fullword ascii
		$s6 = "AntiKill" fullword ascii
		$s7 = "hWndRemove" fullword ascii
		$s8 = "/Clip(watch|Chang|Mon)/" fullword ascii
		$w1 = "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:53.0) Gecko/20100101 Firefox/53.0" fullword wide
		$w2 = "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:56.0) Gecko/20100101 Firefox/56.0" fullword wide
		$w3 = "/create /sc MINUTE /mo 1 /tn \"Windows Service\" /tr \"" fullword wide
		$w4 = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" fullword wide
		$w5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" fullword wide

	condition:
		uint16(0)==0x5a4d and (5 of ($s*) or all of ($w*) or 6 of them )
}
