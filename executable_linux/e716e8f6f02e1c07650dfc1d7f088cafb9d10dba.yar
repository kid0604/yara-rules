rule Linux_Trojan_Winnti_61215d98
{
	meta:
		author = "Elastic Security"
		id = "61215d98-f52d-45d3-afa2-4bd25270aa99"
		fingerprint = "20ee92147edbf91447cca2ee0c47768a50ec9c7aa7d081698953d3bdc2a25320"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Winnti"
		reference_sample = "cc1455e3a479602581c1c7dc86a0e02605a3c14916b86817960397d5a2f41c31"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Winnti variant"
		filetype = "executable"

	strings:
		$a = { FF FF FF C9 C3 55 48 89 E5 48 83 EC 30 89 F8 66 89 45 DC C7 45 FC FF FF }

	condition:
		all of them
}
