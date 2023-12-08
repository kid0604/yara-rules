rule Linux_Exploit_CVE_2016_5195_ea8801ac
{
	meta:
		author = "Elastic Security"
		id = "ea8801ac-ee95-4294-9cfa-99c773a04183"
		fingerprint = "aa191347bdf2e9fdcf6f9591c370b85208a1c46a329bc648268447dbb5ea898f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "7acccfd8c2e5555a3e3bf979ad2314c12a939c1ef32b66e61e30a712f07164fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { 55 48 89 E5 48 83 EC 30 89 7D DC 48 89 75 D0 83 7D DC 02 7F 0A B8 01 00 }

	condition:
		all of them
}
