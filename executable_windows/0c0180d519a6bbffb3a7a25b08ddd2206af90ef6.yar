rule INDICATOR_TOOL_WEDGECUT
{
	meta:
		author = "ditekSHen"
		description = "Detects WEDGECUT a reconnaissance tool to checks hosts are online using ICMP packets"
		clamav1 = "INDICATOR.Win.TOOL.WEDGECUT"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "-name" fullword ascii
		$s2 = "-full" fullword ascii
		$s3 = "\\CheckOnline" ascii
		$s4 = "IcmpSendEcho" fullword ascii
		$s5 = "IcmpCloseHandle" fullword ascii
		$s6 = "IcmpCreateFile" fullword ascii

	condition:
		uint16(0)==0x5a4d and 4 of them
}
