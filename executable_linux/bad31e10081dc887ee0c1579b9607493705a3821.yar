rule Linux_Trojan_Psybnc_563ecb11
{
	meta:
		author = "Elastic Security"
		id = "563ecb11-e215-411f-8583-7cb7b2956252"
		fingerprint = "1e7a2a6240d6f7396505cc2203c03d4ae93a7ef0c0c956cef7a390b4303a2cbe"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Psybnc"
		reference_sample = "f77216b169e8d12f22ef84e625159f3a51346c2b6777a1fcfb71268d17b06d39"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Psybnc"
		filetype = "executable"

	strings:
		$a = { 5F 65 6E 00 6B 6F 5F 65 6E 00 72 75 5F 65 6E 00 65 73 5F 65 6E 00 44 }

	condition:
		all of them
}
