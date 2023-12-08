import "pe"

rule MALWARE_Win_DLAgent03
{
	meta:
		author = "ditekSHen"
		description = "Detects known Delphi downloader agent downloading second stage payload, notably from discord"
		clamav_sig = "MALWARE.Win.Trojan.DLAgent03"
		os = "windows"
		filetype = "executable"

	strings:
		$delph1 = "FastMM Borland Edition" fullword ascii
		$delph2 = "SOFTWARE\\Borland\\Delphi" ascii
		$v1_1 = "InternetOpenUrlA" fullword ascii
		$v1_2 = "CreateFileA" fullword ascii
		$v1_3 = "WriteFile" fullword ascii
		$v2_1 = "WinHttp.WinHttpRequest.5.1" fullword ascii
		$v2_2 = { 6f 70 65 6e ?? ?? ?? ?? ?? 73 65 6e 64 ?? ?? ?? ?? 72 65 73 70 6f 6e 73 65 74 65 78 74 }
		$url1 = "https://discord.com/" fullword ascii
		$url2 = "http://www.superutils.com" fullword ascii
		$url3 = "http://www.xboxharddrive.com" fullword ascii

	condition:
		uint16(0)==0x5a4d and 1 of ($delph*) and 1 of ($url*) and ( all of ($v1*) or 1 of ($v2*))
}
