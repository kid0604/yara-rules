rule SuicideScriptR1_Multi
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects a script attempting to delete itself"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "\" goto R1\ndel /a \""
		$ = "\"\nif exist \""
		$ = "@echo off\n:R1\ndel /a \""

	condition:
		all of them
}
