rule Windows_Generic_MalCert_f11721e1
{
	meta:
		author = "Elastic Security"
		id = "f11721e1-fbcd-40e3-b060-0f7c82da3cdb"
		fingerprint = "eed60c6691c2a82fd6f8bc41f7f89b939d0b90f9ad940ef6111647f0581aeb75"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "42b0c02bc403c0109d79938f70e33deea25109036c2108e248374917fa22f4a9"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows.Generic.MalCert threat"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 01 F5 2E 57 80 3C C7 22 5D 45 43 70 34 2B 2B C7 }

	condition:
		all of them
}
