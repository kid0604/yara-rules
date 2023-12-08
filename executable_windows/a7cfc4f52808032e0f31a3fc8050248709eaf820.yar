rule Windows_Trojan_Smokeloader_ea14b2a5
{
	meta:
		author = "Elastic Security"
		id = "ea14b2a5-ea0d-4da2-8190-dbfcda7330d9"
		fingerprint = "950ce9826fdff209b6e03c70a4f78b812d211a2a9de84bec0e5efe336323001b"
		creation_date = "2023-05-03"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.Smokeloader"
		reference_sample = "15fe237276b9c2c6ceae405c0739479d165b406321891c8a31883023e7b15d54"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Smokeloader"
		filetype = "executable"

	strings:
		$a1 = { AC 41 80 01 AC 41 80 00 AC 41 80 00 AC 41 C0 00 AC 41 80 01 }
		$a2 = { AC 41 80 00 AC 41 80 07 AC 41 80 00 AC 41 80 00 AC 41 80 00 }

	condition:
		all of them
}
