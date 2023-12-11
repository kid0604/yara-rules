rule md5_d201d61510f7889f1a47257d52b15fa2
{
	meta:
		description = "Detects potential PHP code injection via eval function in web requests"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "@eval(stripslashes($_REQUEST[q]));"

	condition:
		any of them
}
