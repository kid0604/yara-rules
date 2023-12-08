rule FeliksPack3___Scanners_ipscan
{
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "6c1bcf0b1297689c8c4c12cc70996a75"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "WCAP;}ECTED"
		$s4 = "NotSupported"
		$s6 = "SCAN.VERSION{_"

	condition:
		all of them
}
