rule Linux_Trojan_Gafgyt_20f5e74f
{
	meta:
		author = "Elastic Security"
		id = "20f5e74f-9f94-431b-877c-9b0d78a1d4eb"
		fingerprint = "070fe0d678612b4ec8447a07ead0990a0abd908ce714388720e7fd7055bf1175"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "9084b00f9bb71524987dc000fb2bc6f38e722e2be2832589ca4bb1671e852f5b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { D8 8B 45 D0 8B 04 D0 8D 50 01 83 EC 0C 8D 85 38 FF FF FF 50 8D 85 40 FF }

	condition:
		all of them
}
