rule PP_CN_APT_ZeroT_9
{
	meta:
		description = "Detects malware from the Proofpoint CN APT ZeroT incident"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.proofpoint.com/us/threat-insight/post/APT-targets-russia-belarus-zerot-plugx"
		date = "2017-02-03"
		hash1 = "a685cf4dca6a58213e67d041bba637dca9cb3ea6bb9ad3eae3ba85229118bce0"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "nflogger.dll" fullword ascii
		$s7 = "Zlh.exe" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <1000KB and all of them )
}
