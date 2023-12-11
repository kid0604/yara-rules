rule md5_ab63230ee24a988a4a9245c2456e4874
{
	meta:
		description = "Detects the use of obfuscated code in various file types"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "eval(gzinflate(base64_decode(str_rot13(strrev("

	condition:
		any of them
}
