rule md5_39ca2651740c2cef91eb82161575348b
{
	meta:
		description = "Detects usage of MD5 hash in PHP code to validate cookie and execute request"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /if\(md5\(@\$_COOKIE\[..\]\)=='.{32}'\) \(\$_=@\$_REQUEST\[.\]\).@\$_\(\$_REQUEST\[.\]\);/

	condition:
		any of them
}
