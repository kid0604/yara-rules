rule Linux_Exploit_CVE_2016_5195_d41c2c63
{
	meta:
		author = "Elastic Security"
		id = "d41c2c63-1af7-47c9-88a0-16454c9583db"
		fingerprint = "77fb7e9911d1037bba0a718d8983a42ad1877c13d865ce415351d599064ea7ea"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.CVE-2016-5195"
		reference_sample = "a4e5751b4e8fa2e9b70e1e234f435a03290c414f9547dc7709ce2ee4263a35f1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2016-5195"
		filetype = "executable"

	strings:
		$a = { F4 83 45 F0 01 81 7D F0 FF C1 EB 0B 7E D3 C9 C3 }

	condition:
		all of them
}
