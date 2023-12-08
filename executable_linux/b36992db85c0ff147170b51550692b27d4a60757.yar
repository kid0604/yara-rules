rule Linux_Trojan_Tsunami_71d31510
{
	meta:
		author = "Elastic Security"
		id = "71d31510-cd2c-4b61-b2cf-975d5ed70c93"
		fingerprint = "6c9f3f31e9dcdcd4b414e79e06f0ae633e50ef3e19a437c1b964b40cc74a57cb"
		creation_date = "2021-12-13"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "33dd6c0af99455a0ca3908c0117e16a513b39fabbf9c52ba24c7b09226ad8626"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 5C B3 C0 19 17 5E 7B 8B 22 16 17 E0 DE 6E 21 46 FB DD 17 67 }

	condition:
		all of them
}
