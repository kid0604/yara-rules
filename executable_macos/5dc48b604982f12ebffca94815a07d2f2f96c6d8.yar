rule MacOS_Virus_Maxofferdeal_4091e373
{
	meta:
		author = "Elastic Security"
		id = "4091e373-c3a9-41c8-a1d8-3a77585ff850"
		fingerprint = "3d8e7db6c39286d9626c6be8bfb5da177a6a4f8ffcec83975a644aaac164a8c7"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Virus.Maxofferdeal"
		reference_sample = "c38c4bdd3c1fa16fd32db06d44d0db1b25bb099462f8d2936dbdd42af325b37c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Virus.Maxofferdeal"
		filetype = "executable"

	strings:
		$a = { B8 F2 E7 E7 BF BF BF E6 AF A7 A7 AF A4 AD E6 AB A7 A5 C8 8B 8E 8A BD A6 AC A4 }

	condition:
		all of them
}
