import "pe"

rule firewallOpener
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects the presence of firewall opener string in PE files"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d \"%s\""

	condition:
		any of them
}
