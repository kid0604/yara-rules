rule Linux_Shellcode_Generic_224bdcc4
{
	meta:
		author = "Elastic Security"
		id = "224bdcc4-4b38-44b5-96c6-d3b378628fa4"
		fingerprint = "e23b239775c321d4326eff2a7edf0787116dd6d8a9e279657e4b2b01b33e72aa"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "bd22648babbee04555cef52bfe3e0285d33852e85d254b8ebc847e4e841b447e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "script"

	strings:
		$a = { 89 E6 6A 10 5A 6A 2A 58 0F 05 48 85 C0 79 1B 49 FF C9 74 22 }

	condition:
		all of them
}
