rule CN_Honker_Master_beta_1_7
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Master_beta_1.7.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "3be7a370791f29be89acccf3f2608fd165e8059e"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "http://seo.chinaz.com/?host=" fullword ascii
		$s2 = "Location: getpass.asp?info=" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <312KB and all of them
}
