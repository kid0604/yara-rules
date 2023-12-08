rule Linux_Trojan_Gafgyt_c573932b
{
	meta:
		author = "Elastic Security"
		id = "c573932b-9b3f-4ab7-a6b6-32dcc7473790"
		fingerprint = "18a3025ebb8af46605970ee8d7d18214854b86200001d576553e102cb71df266"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 83 7D 18 00 74 22 8B 45 1C 83 E0 02 85 C0 74 18 83 EC 08 6A 2D FF }

	condition:
		all of them
}
