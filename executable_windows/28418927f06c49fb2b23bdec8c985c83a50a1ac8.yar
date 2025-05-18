rule Windows_Generic_MalCert_9a68ab4c
{
	meta:
		author = "Elastic Security"
		id = "9a68ab4c-d3ef-46bd-8c33-1f5d2c3352ca"
		fingerprint = "cfff03a13fabfa52c0be548ea670d4038cbca673e28e040d2a8a45f2915efc35"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "8cf87dc9c594d145782807f51404290806a2cbfd7b27a9287bf570393a0cb2da"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 D4 EF 46 9E 41 0A D1 3E 8E 08 DB E2 E9 AC 0F 93 }

	condition:
		all of them
}
