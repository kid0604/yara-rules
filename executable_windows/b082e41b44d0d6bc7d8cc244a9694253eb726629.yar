rule Windows_Generic_Threat_ccb6a7a2
{
	meta:
		author = "Elastic Security"
		id = "ccb6a7a2-6003-4ba0-aefc-3605d085486d"
		fingerprint = "a73b0e067fce2e87c08359b4bb2ba947cc276ff0a07ff9e04cabde529e264192"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "60503212db3f27a4d68bbfc94048ffede04ad37c78a19c4fe428b50f27af7a0d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 40 52 61 6E 67 65 3A 62 79 74 65 73 3D 30 2D }
		$a2 = { 46 49 77 41 36 4B 58 49 75 4E 66 4B 71 49 70 4B 30 4D 57 4D 74 49 38 4B 67 4D 68 49 39 4B 30 4D 53 49 6A 4B 66 4D 73 49 76 4B 75 4D 64 49 70 4B 30 4D 73 49 66 4B 68 4D 6F 49 69 43 6F 4D 6C 49 71 4B }

	condition:
		all of them
}
