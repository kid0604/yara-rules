rule PurpleFox_c
{
	meta:
		id = "5ImXAdrniKP1eF4xcQJpmC"
		fingerprint = "078423ceb734b361b95537288f5d8b96d6c5d91b10fa5728c253131b35f0c201"
		version = "1.0"
		creation_date = "2021-11-01"
		first_imported = "2021-12-30"
		last_modified = "2021-12-30"
		status = "RELEASED"
		sharing = "TLP:WHITE"
		source = "BARTBLAZE"
		author = "@bartblaze"
		description = "Identifies PurpleFox aka DirtyMoe botnet."
		category = "MALWARE"
		os = "windows"
		filetype = "executable"

	strings:
		$ = "UpProxyRandom" ascii wide
		$ = "SetServiceName" ascii wide
		$ = "DrvServiceName" ascii wide
		$ = "DriverOpenName" ascii wide
		$ = "DirLogFilePath" ascii wide
		$ = "RunPeShellPath" ascii wide
		$ = "DriverFileName" ascii wide

	condition:
		all of them
}
