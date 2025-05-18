rule Windows_Generic_MalCert_5f0656b2
{
	meta:
		author = "Elastic Security"
		id = "5f0656b2-cb2d-411a-90c9-d34f5d443b8c"
		fingerprint = "46e7adc1d0ca05f4dc26088246eeda22b32bd263b831a6f2ff648cf3fd870171"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "c35a34aade5c7ac67339549287938171026921c391a3630794ac1393fb829e3a"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 A2 25 3A EB 5B 0F F1 AE CB FD 41 2C 18 CC F0 7A }

	condition:
		all of them
}
