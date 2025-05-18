rule Windows_Generic_MalCert_c3391d33
{
	meta:
		author = "Elastic Security"
		id = "c3391d33-dc53-4fe8-9e83-a72c978d8aff"
		fingerprint = "9211b30243899416df9362898c034ee81f674b09e203db2c47f8044af5d18d6a"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "d0a18627b9cef78997764ee22ece46e76c6f8be01d309d00dff6ca8b56252648"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 11 00 8D AD E4 39 C4 A8 9B 11 48 12 34 B0 B5 0F F6 6F }

	condition:
		all of them
}
