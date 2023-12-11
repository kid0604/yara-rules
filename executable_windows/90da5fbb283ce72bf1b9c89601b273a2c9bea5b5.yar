rule CN_Honker_Interception
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Interception.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "ea813aed322e210ea6ae42b73b1250408bf40e7a"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = ".\\dat\\Hookmsgina.dll" fullword ascii
		$s5 = "WinlogonHackEx " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <160KB and all of them
}
