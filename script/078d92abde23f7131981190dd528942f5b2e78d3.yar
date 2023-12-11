rule SuicideScriptL1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects a script that attempts to delete itself"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = ":L1\ndel \"%s\"\nif exist \"%s\" goto L1\ndel \"%s\"\n"

	condition:
		any of them
}
