rule Linux_Generic_Threat_04e8e4a5
{
	meta:
		author = "Elastic Security"
		id = "04e8e4a5-a1e1-4850-914a-d7e583d052a3"
		fingerprint = "08e48ddeffa8617e7848731b54a17983104240249cddccc5372c16b5d74a1ce4"
		creation_date = "2024-01-23"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "248f010f18962c8d1cc4587e6c8b683a120a1e838d091284ba141566a8a01b92"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 48 81 EC F8 01 00 00 48 8D 7C 24 10 E8 60 13 00 00 48 8D 7C 24 10 E8 12 07 00 00 85 ED 74 30 48 8B 3B 48 8D 54 24 02 48 B8 5B 6B 77 6F 72 6B 65 72 BE 0D 00 00 00 48 89 44 24 02 C7 44 24 0A 2F }

	condition:
		all of them
}
