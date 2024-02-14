rule Linux_Generic_Threat_0d22f19c
{
	meta:
		author = "Elastic Security"
		id = "0d22f19c-5724-480b-95de-ef2609896c52"
		fingerprint = "c1899febb7bf6717bc330577a4baae4b4e81d69c4b3660944a6d8f708652d230"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "da5a204af600e73184455d44aa6e01d82be8b480aa787b28a1df88bb281eb4db"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 49 44 20 25 64 2C 20 45 55 49 44 3A 25 64 20 47 49 44 3A 25 64 2C 20 45 47 49 44 3A 25 64 }
		$a2 = { 50 54 52 41 43 45 5F 50 4F 4B 45 55 53 45 52 20 66 61 75 6C 74 }

	condition:
		all of them
}
