rule Win32_klock
{
	meta:
		description = "Chinese Hacktool Set - file klock.dll"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "7addce4434670927c4efaa560524680ba2871d17"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "klock.dll" fullword ascii
		$s2 = "Erreur : impossible de basculer le bureau ; SwitchDesktop : " fullword wide
		$s3 = "klock de mimikatz pour Windows" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of them
}
