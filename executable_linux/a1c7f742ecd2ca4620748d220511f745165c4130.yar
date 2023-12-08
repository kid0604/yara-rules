rule Linux_Trojan_Dofloo_29c12775
{
	meta:
		author = "Elastic Security"
		id = "29c12775-b7e5-417d-9789-90b9bd4529dd"
		fingerprint = "fbf49f0904e22c4d788f151096f9b1d80aa8c739b31705e6046d17029a6a7a4f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Dofloo"
		reference_sample = "88d826bac06c29e1b9024baaf90783e15d87d2a5c8c97426cbd5a70ae0f99461"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Dofloo"
		filetype = "executable"

	strings:
		$a = { 00 2F 7E 49 00 64 80 49 00 34 7F 49 00 04 7F 49 00 24 80 49 }

	condition:
		all of them
}
