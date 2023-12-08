rule CN_Honker_T00ls_Lpk_Sethc_v4_LPK
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "2b2ab50753006f62965bba83460e3960ca7e1926"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://127.0.0.1/1.exe" fullword wide
		$s2 = "FreeHostKillexe.exe" fullword ascii
		$s3 = "\\sethc.exe /G everyone:F" ascii
		$s4 = "c:\\1.exe" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and 1 of them
}
