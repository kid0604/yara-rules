rule php_malfunctions
{
	meta:
		description = "Detects PHP files with potential malicious functions"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "eval("
		$ = "gzinflate("
		$ = "str_rot13("
		$ = "base64_decode("

	condition:
		3 of them and filesize <500KB
}
