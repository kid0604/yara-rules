import "pe"

rule MALWARE_Win_DLAgent01
{
	meta:
		author = "ditekSHen"
		description = "Detects known downloader agent"
		snort_sid = "920007"
		clamav_sig = "MALWARE.Win.Trojan.DLAgent01"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mozilla/5.0 Gecko/41.0 Firefox/41.0" fullword wide
		$s2 = "/Node:localhost /Namespace:\\\\root\\SecurityCenter2 Path AntiVirusProduct Get displayName /Format:List" fullword wide
		$s3 = "GUID.log" fullword wide
		$s4 = "NO AV" fullword wide
		$s5 = "%d:%I64d:%I64d:%I64d" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
