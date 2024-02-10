rule Windows_Generic_Threat_f0516e98
{
	meta:
		author = "Elastic Security"
		id = "f0516e98-57e1-4e88-b49d-afeff21f6915"
		fingerprint = "c43698c42411080f4df41f0f92948bc5d545f46a060169ee059bb47efefa978c"
		creation_date = "2024-01-31"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "21d01bd53f43aa54f22786d7776c7bc90320ec6f7a6501b168790be46ff69632"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 69 66 20 65 78 69 73 74 20 25 73 20 67 6F 74 6F 20 3A 72 65 70 65 61 74 }
		$a2 = { 41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50 51 52 53 54 55 56 57 58 59 5A 61 62 63 64 65 66 67 68 69 6A 6B 6C 6D 6F 70 71 72 73 74 75 76 77 78 79 7A 30 31 32 33 34 35 36 37 38 39 5F }

	condition:
		all of them
}
