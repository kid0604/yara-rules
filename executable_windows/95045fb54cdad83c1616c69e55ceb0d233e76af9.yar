rule PoisonIvy_Sample_APT_4
{
	meta:
		description = "Detects a PoisonIvy Sample APT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "558f0f0b728b6da537e2666fbf32f3c9c7bd4c0c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Microsoft Software installation Service" fullword wide
		$s1 = "idll.dll" fullword ascii
		$s2 = "mgmts.dll" fullword wide
		$s3 = "Microsoft(R) Windows(R)" fullword wide
		$s4 = "ServiceMain" fullword ascii
		$s5 = "Software installation Service" fullword wide
		$s6 = "SetServiceStatus" fullword ascii
		$s7 = "OriginalFilename" fullword wide
		$s8 = "ZwSetInformationProcess" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 7 of them
}
