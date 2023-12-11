import "pe"

rule MALWARE_Win_DLAgent09
{
	meta:
		author = "ditekSHen"
		description = "Detects known downloader agent"
		os = "windows"
		filetype = "executable"

	strings:
		$h1 = "//:ptth" ascii wide nocase
		$h2 = "//:sptth" ascii wide nocase
		$s1 = "DownloadString" fullword ascii wide
		$s2 = "StrReverse" fullword ascii wide
		$s3 = "FromBase64String" fullword ascii wide
		$s4 = "WebClient" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and (1 of ($h*) and all of ($s*))
}
