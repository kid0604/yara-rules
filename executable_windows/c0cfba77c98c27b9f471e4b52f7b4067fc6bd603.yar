rule Windows_Generic_MalCert_5bcffcb2
{
	meta:
		author = "Elastic Security"
		id = "5bcffcb2-58ec-44d8-9838-3b14090e829f"
		fingerprint = "d40cf9ef781f11f9acb279180a2add28e750a3233a175c4ae538c4702365be47"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "5d1aed7bb03d8ea5ba695916d57d64dfdf4b02a763360eb9ccbf407dea21946a"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 6E 88 9B B3 B7 F7 19 4B 67 4C 6A 03 35 A6 08 E0 }

	condition:
		all of them
}
