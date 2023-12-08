import "pe"

rule MALWARE_Win_DLAgentGo
{
	meta:
		author = "ditekSHen"
		description = "Detects Go-based downloader"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "main.downloadFile" fullword ascii
		$s2 = "main.fetchFiles" fullword ascii
		$s3 = "main.createDefenderAllowanceException" fullword ascii
		$s4 = "main.unzip" fullword ascii
		$s5 = "HideWindow" fullword ascii
		$s6 = "/go/src/installwrap/main.go" ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
