rule md5_2c37d90dd2c9c743c273cb955dd83ef6
{
	meta:
		description = "Detects the use of $_REQUEST variable in PHP scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "@$_($_REQUEST['"

	condition:
		any of them
}
