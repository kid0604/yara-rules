rule CN_Honker_F4ck_Team_F4ck_3
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file F4ck_3.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0b3e9381930f02e170e484f12233bbeb556f3731"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "F4ck.exe" fullword wide
		$s2 = "@Netapi32.dll" fullword ascii
		$s3 = "Team.F4ck.Net" fullword wide
		$s6 = "NO Net Add User" fullword wide
		$s7 = "DLL ERROR" fullword ascii
		$s11 = "F4ck Team" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <100KB and 3 of them
}
