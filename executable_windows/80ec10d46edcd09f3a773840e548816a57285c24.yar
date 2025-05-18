rule Windows_Generic_MalCert_70d7fab0
{
	meta:
		author = "Elastic Security"
		id = "70d7fab0-e626-4f25-964f-b96791408648"
		fingerprint = "e3b25285539c2cf9bc8f9ff596d1df23e6b0fbfe18c1ed6adf883ad23d1fde08"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "c3ef67ddf94f795f7ba18e0e6afc504edbd8ed382699bec299cb1efed9a1788a"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 34 9C 35 32 E8 6E 9E 1B 77 CB CF 7F 12 D0 5C AF }

	condition:
		all of them
}
