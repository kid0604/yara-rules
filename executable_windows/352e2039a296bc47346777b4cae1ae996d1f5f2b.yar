import "pe"

rule MALWARE_Win_NjRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects NjRAT / Bladabindi / NjRAT Golden"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = /Njrat\s\d+\.\d+\sGolden\s/ wide
		$s1 = /\sfirewall\s(add|delete)\sallowedprogram/ wide
		$s2 = { 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 (63|6b) 00 20 00 70 00 69 00 6e 00 67 }
		$s3 = "Execute ERROR" wide
		$s4 = "Download ERROR" wide
		$s5 = "[kl]" fullword wide
		$s6 = "UploadValues" fullword wide
		$s7 = "winmgmts:\\\\.\\root\\SecurityCenter2" fullword wide
		$s8 = "HideM" fullword wide
		$s9 = "No Antivirus" fullword wide

	condition:
		uint16(0)==0x5a4d and 4 of them
}
