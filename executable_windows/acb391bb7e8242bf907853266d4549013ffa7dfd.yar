rule Windows_Generic_MalCert_f20eba4e
{
	meta:
		author = "Elastic Security"
		id = "f20eba4e-3ef3-41c8-8977-452deec74def"
		fingerprint = "4f564659531d3170dd080cad6d6c27b110925c8b8122d88466efeb0e39e92b23"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "511c9272baf722bddd855a16f1b5ec6fc3229c9dc4ab105abfffb79ecc1814ce"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 0A CC D6 0A D2 B2 ED 55 60 F4 67 DD F4 5C EA 0D }

	condition:
		all of them
}
