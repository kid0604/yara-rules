import "pe"

rule createP2P
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects the presence of the CreatP2P Thread"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "CreatP2P Thread" wide

	condition:
		any of them
}
