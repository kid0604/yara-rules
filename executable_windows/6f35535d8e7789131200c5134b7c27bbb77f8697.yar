rule CN_Honker_Sword1_5
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Sword1.5.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "96ee5c98e982aa8ed92cb4cedb85c7fda873740f"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://www.md5.com.cn" fullword wide
		$s2 = "ListBox_Command" fullword wide
		$s3 = "\\Set.ini" wide
		$s4 = "OpenFileDialog1" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <740KB and all of them
}
