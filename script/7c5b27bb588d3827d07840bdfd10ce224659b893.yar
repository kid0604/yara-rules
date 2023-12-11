rule md5_023a80d10d10d911989e115b477e42b5
{
	meta:
		description = "Detects obfuscated strings using chr() function"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /chr\(\d{,3}\)\.\"\"\.chr\(\d{,3}\)/

	condition:
		any of them
}
