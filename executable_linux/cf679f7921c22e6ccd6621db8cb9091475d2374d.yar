rule Linux_Trojan_Mirai_7e9f85fb
{
	meta:
		author = "Elastic Security"
		id = "7e9f85fb-bfc4-4af6-9315-f6e43fefc4ff"
		fingerprint = "ef420ec934e3fd07d5c154a727ed5c4689648eb9ccef494056fed1dea7aa5f9c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "4333e80fd311b28c948bab7fb3f5efb40adda766f1ea4bed96a8db5fe0d80ea1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant 7e9f85fb"
		filetype = "executable"

	strings:
		$a = { 85 50 FF FF FF 0F B6 40 04 3C 07 75 79 48 8B 85 50 FF FF FF }

	condition:
		all of them
}
