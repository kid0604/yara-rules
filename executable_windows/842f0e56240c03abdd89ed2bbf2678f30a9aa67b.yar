import "pe"

rule MALWARE_Win_Bobik
{
	meta:
		author = "ditekSHen"
		description = "Detects Bobik infostealer"
		clamav_sig = "MALWARE.Win.Trojan.Bobik"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "@Default\\Login Data" fullword ascii
		$s2 = "@Default\\Cookies" fullword ascii
		$s3 = "@logins.json" fullword ascii
		$s4 = "@[EXECUTE]" fullword ascii
		$s5 = "@C:\\Windows\\System32\\cmd.exe" fullword ascii
		$s6 = /(CHROME|OPERA|FIREFOX)_BASED/ fullword ascii
		$s7 = "threads.nim" fullword ascii

	condition:
		uint16(0)==0x5a4d and 5 of them
}
