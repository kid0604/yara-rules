rule CN_Honker_hashq_Hashq
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Hashq.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7518b647db5275e8a9e0bf4deda3d853cc9d5661"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Hashq.exe" fullword wide
		$s5 = "CnCert.Net" fullword wide
		$s6 = "Md5 query tool" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
