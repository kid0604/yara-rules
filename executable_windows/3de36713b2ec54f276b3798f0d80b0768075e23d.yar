rule Windows_Generic_MalCert_11e18261
{
	meta:
		author = "Elastic Security"
		id = "11e18261-3d8b-482b-ba45-409877bd1392"
		fingerprint = "8eec08fb6a59ba054a2a10c8200877ee37b9949dfc6b6ff20801aafad8dae1b6"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "249b1bb49496b2db3b4e7e24de90c55deeba21fe328909a7d6fae1533d92ce9a"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 2D 4C 7F 95 4E 56 1C 98 42 F9 B7 D6 }

	condition:
		all of them
}
