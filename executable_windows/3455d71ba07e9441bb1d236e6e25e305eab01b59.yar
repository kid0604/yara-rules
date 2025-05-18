rule Windows_Generic_MalCert_8228dd5b
{
	meta:
		author = "Elastic Security"
		id = "8228dd5b-5ebe-430e-9dcf-5d3abb65c04b"
		fingerprint = "c59df76db61746239de1e750f4e456ae6d0af488550ea05aeb0b2d4a45ffedfd"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "82a6cd7d7e01b7bd2a1c2fc990c9d81a0e09fcef26a28039d2f222e9891bfeff"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Generic.MalCert threat"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 37 E3 20 53 B0 0D 56 23 68 28 E3 D9 }

	condition:
		all of them
}
