import "pe"

rule MALWARE_Win_DLAgent12
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader agent"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WebClient" fullword ascii
		$s2 = "DownloadData" fullword ascii
		$s3 = "packet_server" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them and filesize <50KB
}
