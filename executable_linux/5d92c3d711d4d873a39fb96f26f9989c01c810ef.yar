rule Linux_Cryptominer_Generic_e1ff020a
{
	meta:
		author = "Elastic Security"
		id = "e1ff020a-446c-4537-8cc3-3bcc56ba5a99"
		fingerprint = "363872fe6ef89a0f4c920b1db4ac480a6ae70e80211200b73a804b43377fff01"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Generic"
		reference_sample = "5b611898f1605751a3d518173b5b3d4864b4bb4d1f8d9064cc90ad836dd61812"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux cryptominer"
		filetype = "executable"

	strings:
		$a = { 0F B6 4F 3D 0B 5C 24 F4 41 C1 EB 10 44 0B 5C 24 }

	condition:
		all of them
}
