import "pe"

rule MALWARE_Win_DLAgent02
{
	meta:
		author = "ditekSHen"
		description = "Detects known downloader agent downloading encoded binaries in patches from paste-like websites, most notably hastebin"
		clamav_sig = "MALWARE.Win.Trojan.DLAgent02"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "/c timeout {0}" fullword wide
		$x2 = "^(https?|ftp):\\/\\/" fullword wide
		$x3 = "{0}{1}{2}{3}" wide
		$x4 = "timeout {0}" fullword wide
		$s1 = "HttpWebRequest" fullword ascii
		$s2 = "GetResponseStream" fullword ascii
		$s3 = "set_FileName" fullword ascii
		$s4 = "set_UseShellExecute" fullword ascii
		$s5 = "WebClient" fullword ascii
		$s6 = "set_CreateNoWindow" fullword ascii
		$s7 = "DownloadString" fullword ascii
		$s8 = "WriteByte" fullword ascii
		$s9 = "CreateUrlCacheEntryW" fullword ascii
		$s10 = "HttpStatusCode" fullword ascii
		$s11 = "FILETIME" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and ((2 of ($x*) and 2 of ($s*)) or (#x3>2 and 4 of ($s*)))
}
