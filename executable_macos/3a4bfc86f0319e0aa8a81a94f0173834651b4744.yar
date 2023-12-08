rule INDICATOR_TOOL_PWS_KeychainDumper
{
	meta:
		author = "ditekSHen"
		description = "Detects macOS certificate/password keychain dumping tool"
		clamav_sig = "INDICATOR_Osx.Tool.PWS.KeychainDumper"
		os = "macos"
		filetype = "executable"

	strings:
		$s1 = "_getEmptyKeychainItemString" fullword ascii
		$s2 = "NdumpKeychainEntitlements" fullword ascii
		$s3 = "_dumpKeychainEntitlements" fullword ascii

	condition:
		( uint16(0)==0xfeca or uint16(0)==0xfacf) and all of them
}
