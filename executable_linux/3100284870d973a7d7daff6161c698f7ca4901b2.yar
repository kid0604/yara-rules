rule Linux_Exploit_Lotoor_dbc73db0
{
	meta:
		author = "Elastic Security"
		id = "dbc73db0-527c-436f-afdc-bc3750f10ea0"
		fingerprint = "2f6ad833b84f00be1d385de686a979d3738147c38b4126506e56225080ee81ef"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Lotoor"
		reference_sample = "9fe78e4dd7975856a74d8dfd83e69793a769143e0fe6994cbc3ef28ea37d6cf8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Lotoor malware"
		filetype = "executable"

	strings:
		$a = { 63 75 73 3A 20 4C 69 6E 75 78 20 32 2E 36 2E 33 }

	condition:
		all of them
}
