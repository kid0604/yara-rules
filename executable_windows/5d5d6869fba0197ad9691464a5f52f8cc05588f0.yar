rule Codoso_CustomTCP_alt_1
{
	meta:
		description = "Codoso CustomTCP Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/exploring-bergard-old-malware-new-tricks"
		date = "2016-01-30"
		hash = "b95d7f56a686a05398198d317c805924c36f3abacbb1b9e3f590ec0d59f845d8"
		os = "windows"
		filetype = "executable"

	strings:
		$s4 = "wnyglw" fullword ascii
		$s5 = "WorkerRun" fullword ascii
		$s7 = "boazdcd" fullword ascii
		$s8 = "wayflw" fullword ascii
		$s9 = "CODETABL" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <405KB and all of them
}
