import "pe"

rule MALWARE_Win_DLAgent11
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader agent"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb = "\\loader2\\obj\\Debug\\loader2.pdb" ascii
		$s1 = "DownloadFile" fullword ascii
		$s2 = "ZipFile" fullword ascii
		$s3 = "WebClient" fullword ascii
		$s4 = "ExtractToDirectory" fullword ascii
		$s5 = "System Clear" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or (($pdb) and 4 of ($s*)))
}
