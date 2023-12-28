rule Lazarus_LCPDot_strings
{
	meta:
		description = "LCPDot in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "0c69fd9be0cc9fadacff2c0bacf59dab6d935b02b5b8d2c9cb049e9545bb55ce"
		os = "windows"
		filetype = "executable"

	strings:
		$ua = "Mozilla/5.0 (Windows NT 10.0; WOW64; Trident/7.0; rv:11.0) like Gecko" wide
		$class = "HotPlugin_class" wide
		$post = "Cookie=Enable&CookieV=%d&Cookie_Time=64" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
