rule AutoIT_Script
{
	meta:
		id = "vpilwARgwZCuMLJPuubYB"
		fingerprint = "87dfe76f69bd344860faf3dc46f16b56a2c86a0a3f3763edf8f51860346a16c2"
		version = "1.0"
		creation_date = "2020-09-01"
		first_imported = "2021-12-30"
		last_modified = "2023-10-29"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies AutoIT script."
		category = "MALWARE"
		os = "windows"
		filetype = "script"

	strings:
		$ = "#OnAutoItStartRegister" ascii wide
		$ = "#pragma compile" ascii wide
		$ = "/AutoIt3ExecuteLine" ascii wide
		$ = "/AutoIt3ExecuteScript" ascii wide
		$ = "/AutoIt3OutputDebug" ascii wide
		$ = ">>>AUTOIT NO CMDEXECUTE<<<" ascii wide
		$ = ">>>AUTOIT SCRIPT<<<" ascii wide
		$ = "This is a third-party compiled AutoIt script." ascii wide
		$ = "AU3!EA06" ascii wide

	condition:
		uint16(0)!=0x5A4D and any of them
}
