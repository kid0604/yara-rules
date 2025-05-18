rule Windows_Generic_MalCert_72de26c5
{
	meta:
		author = "Elastic Security"
		id = "72de26c5-b6bf-49f5-84d4-5cf9ec8c673d"
		fingerprint = "fd9564616cd9609c1c01dd6d903aa64a41846664eed9f964a8a8e6d4eb37dca8"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "e74c5cb1bbea30e7abfd292ab134936bb8cd335c52f4fce4bb3994bd6e5024f4"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 9D F8 93 43 AD D6 99 DD C9 8F CD 37 67 DA 5F 84 }

	condition:
		all of them
}
