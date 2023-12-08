rule Linux_Trojan_Getshell_98d002bf
{
	meta:
		author = "Elastic Security"
		id = "98d002bf-63b7-4d11-98ef-c3127e68d59c"
		fingerprint = "b7bfec0a3cfc05b87fefac6b10673491b611400edacf9519cbcc1a71842e9fa3"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Getshell"
		reference_sample = "97b7650ab083f7ba23417e6d5d9c1d133b9158e2c10427d1f1e50dfe6c0e7541"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Getshell malware"
		filetype = "executable"

	strings:
		$a = { B2 6A B0 03 CD 80 85 C0 78 02 FF E1 B8 01 00 00 00 BB 01 00 }

	condition:
		all of them
}
