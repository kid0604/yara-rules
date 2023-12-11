rule Fireball_regkey
{
	meta:
		description = "Detects Fireball malware - file regkey.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/4pTkGQ"
		date = "2017-06-02"
		modified = "2022-12-21"
		hash1 = "fff2818caa9040486a634896f329b8aebaec9121bdf9982841f0646763a1686b"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\WinMain\\Release\\WinMain.pdb" ascii
		$s2 = "ScreenShot" fullword wide
		$s3 = "WINMAIN" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and all of them )
}
