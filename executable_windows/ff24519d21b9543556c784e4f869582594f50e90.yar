rule Nanocore_RAT_Feb18_1
{
	meta:
		description = "Detects Nanocore RAT"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research - T2T"
		date = "2018-02-19"
		hash1 = "aa486173e9d594729dbb5626748ce10a75ee966481b68c1b4f6323c827d9658c"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "NanoCore Client.exe" fullword ascii
		$x2 = "NanoCore.ClientPluginHost" fullword ascii
		$s1 = "PluginCommand" fullword ascii
		$s2 = "FileCommand" fullword ascii
		$s3 = "PipeExists" fullword ascii
		$s4 = "PipeCreated" fullword ascii
		$s5 = "IClientLoggingHost" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (1 of ($x*) or 5 of them )
}
