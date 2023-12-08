rule CN_Honker_Hookmsgina
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Hookmsgina.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f4d9b329b45fbcf6a3b9f29f2633d5d3d76c9f9d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\\\.\\pipe\\WinlogonHack" fullword ascii
		$s2 = "%s?host=%s&domain=%s&user=%s&pass=%s&port=%u" fullword ascii
		$s3 = "Global\\WinlogonHack_Load%u" fullword ascii
		$s4 = "Hookmsgina.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
