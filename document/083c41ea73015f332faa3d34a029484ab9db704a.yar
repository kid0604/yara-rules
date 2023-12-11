rule SUSP_PiratedOffice_2007
{
	meta:
		description = "Detects an Office document that was created with a pirated version of MS Office 2007"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/pwnallthethings/status/743230570440826886?lang=en"
		date = "2018-12-04"
		score = 40
		hash1 = "210448e58a50da22c0031f016ed1554856ed8abe79ea07193dc8f5599343f633"
		os = "windows"
		filetype = "document"

	strings:
		$s7 = "<Company>Grizli777</Company>" ascii

	condition:
		uint16(0)==0xcfd0 and filesize <300KB and all of them
}
