rule MALWARE_Win_Phobos
{
	meta:
		description = "Detect the risk  of Ransomware Phobos Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "\\\\?\\UNC\\\\\\e-" fullword wide
		$x2 = "\\\\?\\ :" fullword wide
		$x3 = "POST" fullword wide
		$s1 = "ELVL" fullword wide
		$s2 = /SUP\d{3}/ fullword wide
		$s3 = { 41 31 47 ?? 41 2b }

	condition:
		uint16(0)==0x5a4d and all of ($x*) and 1 of ($s*)
}
