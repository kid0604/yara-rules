rule Linux_Trojan_Tsunami_30c039e2
{
	meta:
		author = "Elastic Security"
		id = "30c039e2-1c51-4309-9165-e3f2ce79cd6e"
		fingerprint = "4c97fed719ecfc68e7d67268f19aff545447b4447a69814470fe676d4178c0ed"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "b494ca3b7bae2ab9a5197b81e928baae5b8eac77dfdc7fe1223fee8f27024772"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 45 E0 0F B6 00 84 C0 74 1F 48 8B 45 E0 48 8D 50 01 48 8B 45 E8 48 83 }

	condition:
		all of them
}
