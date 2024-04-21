rule Windows_Trojan_Generic_2993e5a5
{
	meta:
		author = "Elastic Security"
		id = "2993e5a5-26b2-4cfd-8130-4779abcfecb2"
		fingerprint = "709015984e3c9abaf141b76bf574921466493475182ca30a56dbc3671030b632"
		creation_date = "2024-03-18"
		last_modified = "2024-03-18"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "9f9b926cef69e879462d9fa914dda8c60a01f3d409b55afb68c3fb94bf1a339b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic with fingerprint 2993e5a5"
		filetype = "executable"

	strings:
		$a = { 0C 8B 45 F0 89 45 C8 8B 45 C8 8B 40 3C 8B 4D F0 8D 44 01 04 89 }

	condition:
		1 of them
}
