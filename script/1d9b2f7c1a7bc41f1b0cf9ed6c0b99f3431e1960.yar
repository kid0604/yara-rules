rule md5_b3ee7ea209d2ff0d920dfb870bad8ce5
{
	meta:
		description = "Detects base64 encoded MySQL key in scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\$mysql_key\s*=\s*@?base64_decode/
		$ = /eval\(\s*\$mysql_key\s*\)/

	condition:
		all of them
}
