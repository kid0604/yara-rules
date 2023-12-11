rule CN_Honker_SwordHonkerEdition
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file SwordHonkerEdition.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3f9479151c2cada04febea45c2edcf5cece1df6c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\bin\\systemini\\MyPort.ini" wide
		$s1 = "PortThread=200 //" fullword wide
		$s2 = " Port Open -> " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <375KB and all of them
}
