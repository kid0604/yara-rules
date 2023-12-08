rule obfuscated_globals
{
	meta:
		description = "Detects obfuscated global variables assignment"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\$GLOBALS\['.{1,10}'\] = "\\x/

	condition:
		any of them
}
