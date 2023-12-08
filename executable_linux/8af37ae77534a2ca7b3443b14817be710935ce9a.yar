rule Linux_Cryptominer_Malxmr_979160f6
{
	meta:
		author = "Elastic Security"
		id = "979160f6-402a-4e4b-858a-374c9415493b"
		fingerprint = "fb933702578e2cf7e8ad74554ef93c07b610d6da8bc5743cbf86c363c1615f40"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { E0 08 C1 ED 10 41 31 C3 89 D8 45 09 D0 C1 E8 10 C1 E3 10 41 C1 }

	condition:
		all of them
}
