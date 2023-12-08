rule CN_Honker_hkmjjiis6
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file hkmjjiis6.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2023-01-27"
		score = 70
		hash = "4cbc6344c6712fa819683a4bd7b53f78ea4047d7"
		os = "windows"
		filetype = "executable"

	strings:
		$s14 = "* FROM IIsWebInfo/r" fullword ascii
		$s19 = "ltithread4ck/" ascii
		$s20 = "LookupAcc=Sid#" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <175KB and all of them
}
