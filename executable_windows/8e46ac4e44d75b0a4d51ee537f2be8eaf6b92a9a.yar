rule CN_Honker_T00ls_Lpk_Sethc_v2
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file T00ls Lpk Sethc v2.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "a995451d9108687b8892ad630a79660a021d670a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "LOADER ERROR" fullword ascii
		$s2 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s3 = "2011-2012 T00LS&RICES" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <800KB and all of them
}
