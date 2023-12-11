rule Codoso_PGV_PVID_5
{
	meta:
		description = "Detects Codoso APT PGV PVID Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		super_rule = 1
		hash1 = "13bce64b3b5bdfd24dc6f786b5bee08082ea736be6536ef54f9c908fd1d00f75"
		hash2 = "bc0b885cddf80755c67072c8b5961f7f0adcaeb67a1a5c6b3475614fd51696fe"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/c del %s >> NUL" fullword ascii
		$s2 = "%s%s.manifest" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
