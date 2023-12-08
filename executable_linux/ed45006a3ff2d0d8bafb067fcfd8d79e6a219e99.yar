rule Linux_Exploit_CVE_2018_10561_0f246e33
{
	meta:
		author = "Elastic Security"
		id = "0f246e33-0e98-4778-8a2f-14876d1a0efe"
		fingerprint = "718b66d3d65d31f0908c8f7d7aee8113e9b51cb576cd725bbca1a23d3ccd4d72"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2018-10561"
		reference_sample = "eac08c105495e6fadd8651d2e9e650b6feba601ec78f537b17fb0e73f2973a1c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2018-10561"
		filetype = "executable"

	strings:
		$a = { 0B DF 0B 75 87 8C 5C 03 03 7A 4B 7A 95 4A A5 D2 13 6A 6A 5A 5A }

	condition:
		all of them
}
