rule INDICATOR_TOOL_PWS_azbelt
{
	meta:
		author = "ditekSHen"
		description = "Detects azbelt for enumerating Azure related credentials primarily on AAD joined machines"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "@http://169.254.169.254/metadata/identity/oauth2/token?api-version=" ascii
		$s2 = "@Partner Customer Delegated Admin Offline Processor" fullword ascii
		$s3 = "@TargetName: " fullword ascii
		$s4 = "httpclient.nim" fullword ascii
		$s5 = "@DSREG_DEVICE_JOIN" fullword ascii
		$s6 = "@.azure/msal_token_cache.bin" fullword ascii
		$s7 = "CredEnumerateW" fullword ascii
		$s8 = "@http://169.254.169.254/metadata/instance?api-version=" ascii

	condition:
		uint16(0)==0x5a4d and 6 of them
}
