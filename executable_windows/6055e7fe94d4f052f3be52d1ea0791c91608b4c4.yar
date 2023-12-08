rule CN_Honker_Churrasco
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file Churrasco.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "5a3c935d82a5ff0546eff51bb2ef21c88198f5b8"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "HEAD9 /" ascii
		$s1 = "logic_er" fullword ascii
		$s6 = "proggam" fullword ascii
		$s16 = "DtcGetTransactionManagerExA" fullword ascii
		$s17 = "GetUserNameA" fullword ascii
		$s18 = "OLEAUT" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1276KB and all of them
}
