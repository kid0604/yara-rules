rule PapaAlfa_alt_1
{
	meta:
		copyright = "2015 Novetta Solutions"
		author = "Novetta Threat Research & Interdiction Group - trig@novetta.com"
		description = "Detects potential indicators of compromise related to PapaAlfa malware variant 1"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "pmsconfig.msi" wide
		$ = "pmslog.msi" wide
		$ = "%sd.e%sc n%ssh%srewa%s ad%s po%sop%sing T%s %d"
		$ = "CreatP2P Thread" wide
		$ = "GreatP2P Thread" wide

	condition:
		3 of them
}
