import "pe"

rule RomeoEcho
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects specific strings related to file operations and execution in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "%s %-20s %10lu %s"
		$ = "_quit"
		$ = "_exe"
		$ = "_put"
		$ = "_get"

	condition:
		all of them
}
