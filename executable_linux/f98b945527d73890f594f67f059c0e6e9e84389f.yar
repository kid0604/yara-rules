rule Linux_Trojan_Meterpreter_383c6708
{
	meta:
		author = "Elastic Security"
		id = "383c6708-0861-4089-93c3-4320bc1e7cfc"
		fingerprint = "6e9da04c91b5846b3b1109f9d907d9afa917fb7dfe9f77780e745d17b799b540"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Meterpreter"
		reference_sample = "d9d607f0bbc101f7f6dc0f16328bdd8f6ddb8ae83107b7eee34e1cc02072cb15"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Meterpreter with ID 383c6708"
		filetype = "executable"

	strings:
		$a = { 99 B6 10 48 89 D6 4D 31 C9 6A 22 41 5A B2 07 0F 05 48 96 48 }

	condition:
		all of them
}
