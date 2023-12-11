rule Linux_Cryptominer_Camelot_0f7c5375
{
	meta:
		author = "Elastic Security"
		id = "0f7c5375-99dc-4204-833a-9128798ed2e9"
		fingerprint = "53bb31c6ba477ed86e55ce31844055c26d7ab7392d78158d3f236d621181ca10"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "e75be5377ad65abdc69e6c7f9fe17429a98188a217d0ca3a6f40e75c4f0c07e8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot malware"
		filetype = "executable"

	strings:
		$a = { F8 7F 48 89 85 C0 00 00 00 77 08 48 83 85 C8 00 00 00 01 31 F6 48 }

	condition:
		all of them
}
