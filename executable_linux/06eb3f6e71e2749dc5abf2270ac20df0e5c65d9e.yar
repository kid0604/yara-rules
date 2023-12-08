rule Linux_Trojan_Ngioweb_e2377400
{
	meta:
		author = "Elastic Security"
		id = "e2377400-8884-42fb-b524-9cdf836dac3a"
		fingerprint = "531a8fcb1c097f72cb9876a35ada622dd1129f90515d84b4c245920602419698"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ngioweb"
		reference_sample = "b88daf00a0e890b6750e691856b0fe7428d90d417d9503f62a917053e340228b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ngioweb"
		filetype = "executable"

	strings:
		$a = { EC 08 8B 5C 24 10 8B 43 20 85 C0 74 72 83 7B 28 00 74 6C 83 7B }

	condition:
		all of them
}
