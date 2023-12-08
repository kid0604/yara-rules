rule Linux_Trojan_Mobidash_2f114992
{
	meta:
		author = "Elastic Security"
		id = "2f114992-36a7-430c-8bd9-5661814d95a8"
		fingerprint = "2371fc5ba1e279a77496328d3a39342408609f04f1a8947e84e734d28d874416"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mobidash"
		reference_sample = "6694640e7df5308a969ef40f86393a65febe51639069cb7eaa5650f62c1f4083"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mobidash"
		filetype = "executable"

	strings:
		$a = { DF 4C 89 F6 48 8B 80 B8 00 00 00 48 8D 64 24 58 5B 5D 41 5C }

	condition:
		all of them
}
