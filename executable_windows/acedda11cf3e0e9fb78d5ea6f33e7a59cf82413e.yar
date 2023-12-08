rule mswin_check_lm_group_alt_1
{
	meta:
		description = "Chinese Hacktool Set - file mswin_check_lm_group.exe"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		modified = "2021-03-15"
		hash = "115d87d7e7a3d08802a9e5fd6cd08e2ec633c367"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Valid_Global_Groups: checking group membership of '%s\\%s'." fullword ascii
		$s2 = "Usage: %s [-D domain][-G][-P][-c][-d][-h]" fullword ascii
		$s3 = "-D    default user Domain" fullword ascii
		$fp1 = "Panda Security S.L." ascii wide

	condition:
		uint16(0)==0x5a4d and filesize <380KB and all of ($s*) and not 1 of ($fp*)
}
