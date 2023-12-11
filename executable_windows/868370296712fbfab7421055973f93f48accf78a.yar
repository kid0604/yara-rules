rule CN_Honker_LPK2_0_LPK
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file LPK.DAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5a1226e73daba516c889328f295e728f07fdf1c3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\sethc.exe /G everyone:F" ascii
		$s2 = "net1 user guest guest123!@#" fullword ascii
		$s3 = "\\dllcache\\sethc.exe" ascii
		$s4 = "sathc.exe 211" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1030KB and all of them
}
