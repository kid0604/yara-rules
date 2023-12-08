rule PoisonIvy_Sample_5
{
	meta:
		description = "Detects PoisonIvy RAT sample set"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "545e261b3b00d116a1d69201ece8ca78d9704eb2"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Microsoft Software installation Service" fullword wide
		$s2 = "pidll.dll" fullword ascii
		$s3 = "\\mspmsnsv.dll" ascii
		$s4 = "\\sfc.exe" ascii
		$s13 = "ServiceMain" fullword ascii
		$s15 = "ZwSetInformationProcess" fullword ascii
		$s17 = "LookupPrivilegeValueA" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
