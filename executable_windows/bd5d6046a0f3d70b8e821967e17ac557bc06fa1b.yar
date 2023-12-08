import "pe"

rule IndiaBravo_PapaAlfa
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects the presence of IndiaBravo_PapaAlfa malware"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "pmsconfig.msi" wide
		$ = "scvrit001.bat"

	condition:
		all of them
}
