rule Windows_Generic_MalCert_148ea98b
{
	meta:
		author = "Elastic Security"
		id = "148ea98b-a8ce-49b5-9808-289cdb7e0487"
		fingerprint = "9ddf8a9172c025d884f64f9e65159159d6e33daca7c13aeccf96372c7f5dccb0"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "eb8ddf6ffbb1ad3e234418b0f5fb0e6191a8c8a72f8ee460ae5f64ffa5484f3b"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 D5 E3 54 50 B8 47 E0 61 38 C2 B4 74 49 25 D9 67 }

	condition:
		all of them
}
