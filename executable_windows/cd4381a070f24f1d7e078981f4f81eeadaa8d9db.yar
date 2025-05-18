rule Windows_Generic_MalCert_401d2001
{
	meta:
		author = "Elastic Security"
		id = "401d2001-83bd-4575-bb8c-ed7d6fd1288d"
		fingerprint = "c40d33db3adfb1bcb96c58ada22b0380b259d43eeedba1e7cd8bb551ab5c5072"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "6dae04b373b1642e77163a392a14101c05f95f45445f33a171232fa8c921e3fc"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 4A CE 35 43 66 56 43 D3 AF 3E AD E4 }

	condition:
		all of them
}
