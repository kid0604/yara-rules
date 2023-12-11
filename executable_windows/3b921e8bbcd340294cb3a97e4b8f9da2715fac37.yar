rule CN_Honker_Layer_Layer
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Layer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2022-12-21"
		score = 70
		hash = "0f4f27e842787cb854bd61f9aca86a63f653eb41"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Release\\Layer.pdb" ascii
		$s2 = "Layer.exe" fullword wide
		$s3 = "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:26.0) Gecko/20100101 Firefox/26.0" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
