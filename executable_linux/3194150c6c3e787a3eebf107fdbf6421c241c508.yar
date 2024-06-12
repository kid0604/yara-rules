rule Linux_Generic_Threat_be02b1c9
{
	meta:
		author = "Elastic Security"
		id = "be02b1c9-fb48-434c-a0ee-a1a87938992c"
		fingerprint = "c803bfffa481ad01bbfe490f9732748f8988669eab6bdf9f1e0e55f5ba8917a3"
		creation_date = "2024-05-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "ef6d47ed26f9ac96836f112f1085656cf73fc445c8bacdb737b8be34d8e3bcd2"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 18 48 89 FB 48 89 F5 48 8B 47 08 48 89 C2 48 C1 EA 18 88 14 24 48 89 C2 48 C1 EA 10 88 54 24 01 48 89 C2 48 C1 EA 08 88 54 24 02 88 44 24 03 48 8B 07 48 89 C2 48 C1 EA 18 88 54 24 04 }

	condition:
		all of them
}
