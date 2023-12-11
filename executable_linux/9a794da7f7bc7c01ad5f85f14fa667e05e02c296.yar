rule Linux_Hacktool_Bruteforce_bad95bd6
{
	meta:
		author = "Elastic Security"
		id = "bad95bd6-94a9-4abf-9d3b-781f0b79c5ce"
		fingerprint = "10698122ff9fe06b398307ec15ad4f5bb519285e1eaad97011abf0914f1e7afd"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Bruteforce"
		reference_sample = "8e8be482357ebddc6ac3ea9ee60241d011063f7e558a59e6bd119e72e4862024"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Bruteforce malware"
		filetype = "executable"

	strings:
		$a = { 73 65 6E 64 6D 6D 73 67 00 66 70 75 74 73 00 6D 65 6D 63 70 79 00 }

	condition:
		all of them
}
