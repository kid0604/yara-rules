rule redSails_EXE
{
	meta:
		description = "Detects Red Sails Hacktool by WinDivert references"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/BeetleChunks/redsails"
		date = "2017-10-02"
		hash1 = "7a7861d25b0c038d77838ecbd5ea5674650ad4f5faf7432a6f3cfeb427433fac"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bWinDivert64.dll" fullword ascii
		$s2 = "bWinDivert32.dll" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <6000KB and all of them )
}
