rule Windows_Generic_MalCert_024569d4
{
	meta:
		author = "Elastic Security"
		id = "024569d4-aa57-4aaa-9e93-afea6f73ae3a"
		fingerprint = "c2142515db4cc4f86a0ee389746f4f555e05a2a868596315dfe72dbce4bcce2a"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "fa3614bbfbe3ccdee5262a4ad0ae4808cb0e689cde22eddaf30dd8eb23b0440b"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 25 06 C0 C5 BA 74 E2 F6 01 FD 8F D8 F4 4B 79 A1 }

	condition:
		all of them
}
