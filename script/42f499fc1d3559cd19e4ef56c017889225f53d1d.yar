rule md5_4aa900ddd4f1848a15c61a9b7acd5035
{
	meta:
		description = "Detects the use of base64 decoding in strings"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "'base'.(128/2).'_de'.'code'"

	condition:
		any of them
}
