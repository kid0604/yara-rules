rule APT_Malware_PutterPanda_PSAPI
{
	meta:
		description = "Detects a malware related to Putter Panda"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		score = 70
		reference = "VT Analysis"
		date = "2015-06-03"
		hash = "f93a7945a33145bb6c106a51f08d8f44eab1cdf5"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "LOADER ERROR" fullword ascii
		$s1 = "The procedure entry point %s could not be located in the dynamic link library %s" fullword ascii
		$s2 = "psapi.dll" fullword ascii
		$s3 = "urlmon.dll" fullword ascii
		$s4 = "WinHttpGetProxyForUrl" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
