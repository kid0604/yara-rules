rule Linux_Trojan_Snessik_e435a79c
{
	meta:
		author = "Elastic Security"
		id = "e435a79c-4b8e-42de-8d78-51b684eba178"
		fingerprint = "bd9f81d03812e49323b86b2ea59bf5f08021d0b43f7629eb4d59e75eccb7dcf1"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Snessik"
		reference_sample = "e24749b07f824a4839b462ec4e086a4064b29069e7224c24564e2ad7028d5d60"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Snessik malware"
		filetype = "executable"

	strings:
		$a = { C6 75 38 31 C0 48 8B 5C 24 68 48 8B 6C 24 70 4C 8B 64 24 78 4C 8B AC 24 80 00 }

	condition:
		all of them
}
