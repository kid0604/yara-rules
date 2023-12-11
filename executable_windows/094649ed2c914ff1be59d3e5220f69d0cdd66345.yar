rule CN_Honker_windows_exp
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file exp.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "04334c396b165db6e18e9b76094991d681e6c993"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "c:\\windows\\system32\\command.com /c " fullword ascii
		$s8 = "OH,Sry.Too long command." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <220KB and all of them
}
