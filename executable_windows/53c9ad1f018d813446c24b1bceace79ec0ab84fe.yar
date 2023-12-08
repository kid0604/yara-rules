rule CN_Honker_F4ck_Team_f4ck_3
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file f4ck.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7e3bf9b26df08cfa10f10e2283c6f21f5a3a0014"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "File UserName PassWord [comment] /add" fullword ascii
		$s2 = "No Net.exe Add User" fullword ascii
		$s3 = "BlackMoon RunTime Error:" fullword ascii
		$s4 = "Team.F4ck.Net" fullword wide
		$s5 = "admin 123456789" fullword ascii
		$s6 = "blackmoon" fullword ascii
		$s7 = "f4ck Team" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 4 of them
}
