import "pe"

rule SierraBravo_packed
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects packed files associated with SierraBravo malware"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "cmd.exe /c \"net share admin$ /d\""
		$ = "MAIL FROM:<"
		$ = ".petite"
		$ = "Subject: %s|%s|%s"

	condition:
		3 of them
}
