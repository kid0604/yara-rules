rule Windows_Generic_Threat_7693d7fd
{
	meta:
		author = "Elastic Security"
		id = "7693d7fd-4161-4afb-8a8d-d487f2a7de5e"
		fingerprint = "92489c8eb4f8a9da5e7bd858a47e20b342d70df1ba3a4769df06c434dc83d138"
		creation_date = "2024-02-13"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fc40cc5d0bd3722126302f74ace414e6934eca3a8a5c63a11feada2130b34b89"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat based on specific fingerprint"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 51 51 8B 45 08 83 65 FC 00 8B 00 0F B7 48 14 66 83 78 06 00 8D 4C 01 18 0F 86 9A 00 00 00 53 56 57 8D 59 24 8B 13 8B CA 8B F2 C1 E9 1D C1 EE 1E 8B FA 83 E1 01 83 E6 01 C1 EF 1F F7 C2 }

	condition:
		all of them
}
