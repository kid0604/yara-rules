rule Windows_Generic_Threat_7bb75582
{
	meta:
		author = "Elastic Security"
		id = "7bb75582-ffcd-4a91-8816-811a3f9bdec8"
		fingerprint = "326a08e467cbedb01c640232ad2f4da729894f09ccf5faba93926e1efded9b59"
		creation_date = "2024-03-04"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "35f9698e9b9f611b3dd92466f18f97f4a8b4506ed6f10d4ac84303177f43522d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 4B 45 59 5F 43 55 52 52 45 4E 54 5F 55 53 45 52 5C 53 6F 66 74 77 61 72 65 5C 4D 69 63 72 6F 73 6F 66 74 5C 57 69 6E 64 6F 77 73 5C 43 75 72 72 65 6E 74 56 65 72 73 69 6F 6E 5C 49 6E 74 65 72 6E 65 74 20 53 65 74 74 69 6E 67 73 5C 43 6F 6E 6E 65 63 74 69 6F 6E 73 20 5B 31 20 37 20 31 37 5D }

	condition:
		all of them
}
