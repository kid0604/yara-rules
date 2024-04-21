rule Windows_Generic_Threat_54ccad4d
{
	meta:
		author = "Elastic Security"
		id = "54ccad4d-3b8d-4abb-88eb-d428d661169d"
		fingerprint = "4fe13c4ca3569912978a0c2231ec53a715a314e1158e09bc0c61f18151cfffa3"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "fe4aad002722d2173dd661b7b34cdb0e3d4d8cd600e4165975c48bf1b135763f"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat based on specific strings"
		filetype = "executable"

	strings:
		$a1 = { 4D 55 73 65 72 4E 61 74 69 66 65 72 63 }
		$a2 = { 4D 79 52 65 67 53 61 76 65 52 65 63 6F 72 64 }
		$a3 = { 53 74 65 61 6C 65 72 54 69 6D 65 4F 75 74 }

	condition:
		all of them
}
