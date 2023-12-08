import "pe"

rule MALWARE_Win_DLAgent06
{
	meta:
		author = "ditekSHen"
		description = "Detects known downloader agent downloading encoded binaries in patches"
		snort2_sid = "920122"
		snort3_sid = "920119"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "totallist" fullword ascii wide
		$s2 = "LINKS_HERE" fullword wide
		$s3 = "[SPLITTER]" fullword wide
		$var2_1 = "DownloadWeb" fullword ascii
		$var2_2 = "WriteByte" fullword ascii
		$var2_3 = "MemoryStream" fullword ascii
		$var2_4 = "DownloadString" fullword ascii
		$var2_5 = "WebClient" fullword ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($s*) and 2 of ($var2*)) or (4 of ($var2*) and 2 of ($s*)))
}
