rule PoisonIvy_Sample_7
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "9480cf544beeeb63ffd07442233eb5c5f0cf03b3"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Microsoft Software installation Service" fullword wide
		$s2 = "pidll.dll" fullword ascii
		$s10 = "ServiceMain" fullword ascii
		$s11 = "ZwSetInformationProcess" fullword ascii
		$s12 = "Software installation Service" fullword wide
		$s13 = "Microsoft(R) Windows(R) Operating System" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
