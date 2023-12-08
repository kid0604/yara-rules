rule Partial_Implant_ID
{
	meta:
		author = "NCSC"
		description = "Detects implant from NCSC report"
		reference = "https://www.ncsc.gov.uk/alerts/hostile-state-actors-compromising-uk-organisations-focus-engineering-and-industrial-control"
		date = "2018/04/06"
		hash = "b5278301da06450fe4442a25dda2d83d21485be63598642573f59c59e980ad46"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = {38 38 31 34 35 36 46 43}

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and all of ($a*)
}
