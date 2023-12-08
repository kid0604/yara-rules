rule CN_Honker_exp_iis7
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file iis7.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "0a173c5ece2fd4ac8ecf9510e48e95f43ab68978"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\\\localhost" fullword ascii
		$s1 = "iis.run" fullword ascii
		$s3 = ">Could not connecto %s" fullword ascii
		$s4 = "WinSta0\\Default" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <60KB and all of them
}
