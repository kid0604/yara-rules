rule Linux_Hacktool_Bruteforce_eb83b6aa
{
	meta:
		author = "Elastic Security"
		id = "eb83b6aa-d7b5-4d10-9258-4bf619fc6582"
		fingerprint = "7767bf57c57d398f27646f5ae2bcda07d6c62959becb31a5186ff0b027ff02b4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Bruteforce"
		reference_sample = "8dec88576f61f37fbaece3c30e71d338c340c8fb9c231f9d7b1c32510d2c3167"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Bruteforce"
		filetype = "executable"

	strings:
		$a = { 10 89 45 EC EB 04 83 6D EC 01 83 7D EC 00 74 12 8B 45 EC 8D }

	condition:
		all of them
}
