rule CN_Honker_SkinHRootkit_SkinH
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SkinH.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d593f03ae06e54b653c7850c872c0eed459b301f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "(C)360.cn Inc.All Rights Reserved." fullword wide
		$s1 = "SDVersion.dll" fullword wide
		$s2 = "skinh.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2000KB and all of them
}
