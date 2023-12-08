import "pe"

rule MALWARE_Win_Phonzy
{
	meta:
		author = "ditekSHen"
		description = "Detects specific downloader agent"
		os = "windows"
		filetype = "executable"

	strings:
		$ua1 = "User-Agent: Mozilla/5.0 (X11; Linux" wide
		$s1 = "<meta name=\"keywords\" content=\"([\\w\\d ]*)\">" fullword wide
		$s2 = "WebClient" fullword ascii
		$s3 = "WriteAllText" fullword ascii
		$s4 = "DownloadString" fullword ascii
		$s5 = "WriteByte" fullword ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($s*) or (1 of ($ua*) and ($s1) and 2 of ($s*)))
}
