rule Linux_Trojan_Xhide_cd8489f7
{
	meta:
		author = "Elastic Security"
		id = "cd8489f7-795f-4fd5-b9a6-03ddd0f3bad4"
		fingerprint = "30b2e0a8ad2fdaa040d748d8660477ae93a6ebc89a186029ff20392f6c968578"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xhide"
		reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xhide"
		filetype = "executable"

	strings:
		$a = { 6F 74 2E 63 6F 6E 66 0A 0A 00 46 75 6C 6C 20 70 61 74 68 20 }

	condition:
		all of them
}
