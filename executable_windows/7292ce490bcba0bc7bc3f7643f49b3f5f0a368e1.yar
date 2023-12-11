import "pe"

rule MALWARE_Win_TOITOIN_Downloader
{
	meta:
		author = "ditekSHen"
		description = "Detects TOITOIN Downloader"
		clamav = "ditekSHen.MALWARE.Win.Trojan.TOITOIN"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = ":\\Trabalho_2023\\OFF_2023\\" ascii
		$s1 = { 20 2f 63 20 22 [6-15] 63 00 6d 00 64 00 00 00 6f 00 70 00 65 00 6e }
		$o1 = { 48 83 fa 10 72 34 48 8b 8d 10 ?? 00 00 48 ff c2 }

	condition:
		uint16(0)==0x5a4d and all of them
}
