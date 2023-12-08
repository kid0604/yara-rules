rule CN_Honker_exp_win2003
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file win2003.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "47164c8efe65d7d924753fadf6cdfb897a1c03db"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Usage:system_exp.exe \"cmd\"" fullword ascii
		$s2 = "The shell \"cmd\" success!" fullword ascii
		$s4 = "Not Windows NT family OS." fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <100KB and all of them
}
