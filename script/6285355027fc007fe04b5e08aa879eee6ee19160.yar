rule overwrite_globals_hack
{
	meta:
		description = "Detects potential hack attempt by overwriting global variables"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /\$GLOBALS\['[^']{,20}'\]=Array\(/

	condition:
		any of them
}
