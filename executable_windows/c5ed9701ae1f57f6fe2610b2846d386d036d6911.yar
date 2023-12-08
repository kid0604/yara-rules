import "pe"

rule MALWARE_Win_DLAgent04
{
	meta:
		author = "ditekSHen"
		description = "Detects known downloader agent downloading encoded binaries in patches from paste-like websites, most notably hastebin"
		clamav_sig = "MALWARE.Win.Trojan.DLAgent04"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "@@@http" ascii wide
		$s1 = "HttpWebRequest" fullword ascii
		$s2 = "GetResponseStream" fullword ascii
		$s3 = "set_FileName" fullword ascii
		$s4 = "set_UseShellExecute" fullword ascii
		$s5 = "WebClient" fullword ascii
		$s6 = "set_CreateNoWindow" fullword ascii
		$s7 = "DownloadString" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and #x1>1 and 4 of ($s*)
}
