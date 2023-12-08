rule CN_Honker_Codeeer_Explorer
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Codeeer Explorer.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f32e05f3fefbaa2791dd750e4a3812581ce0f205"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "Codeeer Explorer.exe" fullword wide
		$s12 = "webBrowser1_ProgressChanged" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <470KB and all of them
}
