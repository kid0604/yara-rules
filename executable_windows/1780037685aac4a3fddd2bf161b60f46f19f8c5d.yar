rule CN_Honker_SwordCollEdition
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SwordCollEdition.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "6e14f21cac6e2aa7535e45d81e8d1f6913fd6e8b"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "YuJianScan.exe" fullword wide
		$s1 = "YuJianScan" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <225KB and all of them
}
