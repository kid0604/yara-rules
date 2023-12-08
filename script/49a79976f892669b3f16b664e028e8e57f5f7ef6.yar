rule SuicideScriptR_alt_1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects a suicide script that deletes itself and another file"
		os = "windows"
		filetype = "script"

	strings:
		$ = ":R\nIF NOT EXIST %s GOTO E\ndel /a %s\nGOTO R\n:E\ndel /a d.bat"

	condition:
		all of them
}
