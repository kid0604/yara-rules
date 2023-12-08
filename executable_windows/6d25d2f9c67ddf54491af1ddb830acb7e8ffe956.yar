import "pe"

rule MALWARE_Win_RookIE_Downloader
{
	meta:
		author = "ditekSHen"
		description = "Detect malware downlaoder, variant of ZombieBoy downloader"
		clamav1 = "MALWARE.Win.Trojan.RookIE-Downloader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "shell:::{2559a1f3-21d7-11d4-bdaf-00c04f60b9f0}" fullword ascii
		$s2 = "taskkill /f /im hh.exe" fullword ascii
		$s3 = "RookIE/1.0" fullword ascii
		$s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\0" fullword ascii
		$s5 = "#32770" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
