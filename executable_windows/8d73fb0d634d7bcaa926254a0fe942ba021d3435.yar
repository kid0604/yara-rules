rule Windows_Generic_MalCert_b19d9b4b
{
	meta:
		author = "Elastic Security"
		id = "b19d9b4b-ef9f-4d6a-8c1a-8fb112f317e7"
		fingerprint = "8c16b78a0d4148c5bec13e07955ddb57485090dc88c802844d8e387dfea25311"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "217f09c89a67f223d9b370507eb5433542416a6c1f1a50f2047fb9355dceb55f"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 01 25 76 8E 32 D5 78 53 C5 79 F0 E2 16 3E C3 90 }

	condition:
		all of them
}
