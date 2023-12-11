rule APT_MAL_MalDoc_CloudAtlas_Oct20_1
{
	meta:
		description = "Detects unknown maldoc dropper noticed in October 2020"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/jfslowik/status/1316050637092651009"
		date = "2020-10-13"
		hash1 = "7ba76b2311736dbcd4f2817c40dae78f223366f2404571cd16d6676c7a640d70"
		os = "windows"
		filetype = "document"

	strings:
		$x1 = "https://msofficeupdate.org" wide

	condition:
		uint16(0)==0xcfd0 and filesize <300KB and 1 of ($x*)
}
