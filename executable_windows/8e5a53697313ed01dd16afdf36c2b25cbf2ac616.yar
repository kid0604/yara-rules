rule Dos_NtGod
{
	meta:
		description = "Chinese Hacktool Set - file NtGod.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "adefd901d6bbd8437116f0170b9c28a76d4a87bf"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\temp\\NtGodMode.exe" ascii
		$s4 = "NtGodMode.exe" fullword ascii
		$s10 = "ntgod.bat" fullword ascii
		$s19 = "sfxcmd" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <250KB and all of them
}
