rule CN_Honker_T00ls_Lpk_Sethc_v3_LPK
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cf2549bbbbdb7aaf232d9783873667e35c8d96c1"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "FreeHostKillexe.exe" fullword ascii
		$s2 = "\\sethc.exe /G everyone:F" ascii
		$s3 = "c:\\1.exe" fullword ascii
		$s4 = "Set user Group Error! Username:" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <400KB and all of them
}
