rule CN_Honker_NetFuke_NetFuke
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file NetFuke.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f89e223fd4f6f5a3c2a2ea225660ef0957fc07ba"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mac Flood: Flooding %dT %d p/s " fullword ascii
		$s2 = "netfuke_%s.txt" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1840KB and all of them
}
