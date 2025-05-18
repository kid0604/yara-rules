rule Windows_Generic_MalCert_09dd7d76
{
	meta:
		author = "Elastic Security"
		id = "09dd7d76-7fb5-4e6a-8d26-5cc8b350d56c"
		fingerprint = "43174658c61a70035102d1bd59c887f743532ee15ba6a3099d59d085b2a418f8"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "501f636706a737a1186d37a8656b488957a4371b2dd7fcc77f13d5530278719e"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 02 D3 48 95 65 F0 54 1F 0A EC 61 84 A4 98 1D 81 }

	condition:
		all of them
}
