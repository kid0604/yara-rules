rule Linux_Trojan_Gafgyt_5bf62ce4
{
	meta:
		author = "Elastic Security"
		id = "5bf62ce4-619b-4d46-b221-c5bf552474bb"
		fingerprint = "3ffc398303f7208e77c4fbdfb50ac896e531b7cee3be2fa820bc8d70cfb20af3"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "4c6aeaa6f6a0c40a3f4116a2e19e669188a8b1678a8930350889da1bab531c68"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 5bf62ce4"
		filetype = "executable"

	strings:
		$a = { 89 E5 56 53 31 F6 8D 45 10 83 EC 10 89 45 F4 8B 55 F4 46 8D }

	condition:
		all of them
}
