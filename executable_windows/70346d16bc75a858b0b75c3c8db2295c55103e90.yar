rule CN_Honker_T00ls_Lpk_Sethc_v4_0
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v4.0.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "98f21f72c761e504814f0a7db835a24a2413a6c2"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "LOADER ERROR" fullword ascii
		$s15 = "2011-2012 T00LS&RICES" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <2077KB and all of them
}
