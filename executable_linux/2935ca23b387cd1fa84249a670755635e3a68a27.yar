rule Linux_Cryptominer_Stak_d707fd3a
{
	meta:
		author = "Elastic Security"
		id = "d707fd3a-41ce-4f88-ad42-d663094db5fb"
		fingerprint = "c218a3c637f58a6e0dc2aa774eb681757c94e1d34f622b4ee5520985b893f631"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Stak"
		reference_sample = "d0d2bab33076121cf6a0a2c4ff1738759464a09ae4771c39442a865a76daff59"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Stak malware"
		filetype = "executable"

	strings:
		$a = { C2 01 48 89 10 49 8B 55 00 48 8B 02 48 8B 4A 10 48 39 C8 74 9E 80 }

	condition:
		all of them
}
