rule Linux_Trojan_Tsunami_2462067e
{
	meta:
		author = "Elastic Security"
		id = "2462067e-06cf-409c-8184-86bd7a772690"
		fingerprint = "f84d62ad2d6f907a47ea9ff565619648564b7003003dc8f20e28a582a8331e6b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "3847f1c7c15ce771613079419de3d5e8adc07208e1fefa23f7dd416b532853a1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 8B 45 F4 8B 40 0C 89 C1 8B 45 F4 8B 40 10 8B 10 8D 45 E4 89 C7 }

	condition:
		all of them
}
