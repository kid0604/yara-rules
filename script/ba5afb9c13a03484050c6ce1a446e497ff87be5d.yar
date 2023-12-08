rule obf_base64_decode
{
	meta:
		description = "Detects obfuscated base64 decode strings"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "\\x62\\x61\\x73\\145\\x36\\x34\\x5f\\x64\\x65\\143\\x6f\\144\\145"

	condition:
		any of them and filesize <500KB
}
