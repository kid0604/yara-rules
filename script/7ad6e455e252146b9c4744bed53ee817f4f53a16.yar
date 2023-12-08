rule Linux_Shellcode_Generic_30c70926
{
	meta:
		author = "Elastic Security"
		id = "30c70926-9414-499a-a4db-7c3bb902dd82"
		fingerprint = "4af586211c56e92b1c60fcd09b4def9801086fbe633418459dc07839fe9c735a"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "a742e23f26726293b1bff3db72864471d6bb4062db1cc6e1c4241f51ec0e21b1"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "script"

	strings:
		$a = { E3 52 53 89 E1 31 C0 B0 0B CD 80 31 C0 40 CD 80 }

	condition:
		all of them
}
