rule CN_Honker_HconSTFportable
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file HconSTFportable.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "00253a00eadb3ec21a06911a3d92728bbbe80c09"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "HconSTFportable.exe" fullword wide
		$s2 = "www.Hcon.in" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <354KB and all of them
}
