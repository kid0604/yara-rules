import "pe"

rule MALWARE_Win_CobianRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects CobianRAT, a fork of Njrat"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "1.0.40.7" fullword wide
		$s2 = "DownloadData" fullword wide
		$s3 = "Executed As" fullword wide
		$s4 = "\\Plugins" fullword wide
		$s5 = "LOGIN" fullword wide
		$s6 = "software\\microsoft\\windows\\currentversion\\run" wide
		$s7 = "Hidden" fullword wide

	condition:
		uint16(0)==0x5a4d and 5 of them
}
