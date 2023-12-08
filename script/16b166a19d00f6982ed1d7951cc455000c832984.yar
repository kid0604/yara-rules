rule md5_2495b460f28f45b40d92da406be15627
{
	meta:
		description = "Detects a specific MD5 hash related to a file copy operation"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "$dez = $pwddir.\"/\".$real;copy($uploaded, $dez);"

	condition:
		any of them
}
