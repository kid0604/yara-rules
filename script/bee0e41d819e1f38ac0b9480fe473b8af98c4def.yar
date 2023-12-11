rule CN_Honker_F4ck_Team_f4ck_alt_1
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file f4ck.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e216f4ba3a07de5cdbb12acc038cd8156618759e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "PassWord:F4ckTeam!@#" fullword ascii
		$s1 = "UserName:F4ck" fullword ascii
		$s2 = "F4ck Team" fullword ascii

	condition:
		filesize <1KB and all of them
}
