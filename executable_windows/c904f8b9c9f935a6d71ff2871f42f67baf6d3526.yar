rule CN_Honker_T00ls_Lpk_Sethc_v3_0
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v3.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "fa47c4affbac01ba5606c4862fdb77233c1ef656"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://127.0.0.1/1.exe" fullword wide
		$s2 = ":Rices  Forum:T00Ls.Net  [4 Fucker Te@m]" fullword wide
		$s3 = "SkinH_EL.dll" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and 2 of them
}
