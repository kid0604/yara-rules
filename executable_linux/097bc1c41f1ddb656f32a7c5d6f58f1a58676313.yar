rule Linux_Trojan_Xhide_840b27c7
{
	meta:
		author = "Elastic Security"
		id = "840b27c7-191f-4d31-9b46-f22be634b2af"
		fingerprint = "f1281db9a49986e23ef1fd9a97785d3bd7c9b3b855cf7e51744487242dd395a3"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xhide"
		reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xhide (840b27c7) based on specific strings"
		filetype = "executable"

	strings:
		$a = { 8B 45 98 83 E0 40 85 C0 75 16 8B 45 98 83 E0 08 85 C0 75 0C 8B }

	condition:
		all of them
}
