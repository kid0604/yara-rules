rule Linux_Trojan_Kaiji_91091be3
{
	meta:
		author = "Elastic Security"
		id = "91091be3-8c9e-4d7a-8ca6-cd422afe0aa5"
		fingerprint = "f583bbef07f41e74ba9646a3e97ef114eb34b1ae820ed499dffaad90db227ca6"
		creation_date = "2022-09-12"
		last_modified = "2022-10-18"
		threat_name = "Linux.Trojan.Kaiji"
		reference_sample = "dca574d13fcbd7d244d434fcbca68136e0097fefc5f131bec36e329448f9a202"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Kaiji"
		filetype = "executable"

	strings:
		$a = { 24 18 83 7C 24 1C 02 75 9E 8B 4C 24 64 8B 51 1C 89 54 24 5C }

	condition:
		all of them
}
