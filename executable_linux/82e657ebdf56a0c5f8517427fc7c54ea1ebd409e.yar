rule Linux_Hacktool_Flooder_a44ab8cd
{
	meta:
		author = "Elastic Security"
		id = "a44ab8cd-c45e-4fe8-b96d-d4fe227f3107"
		fingerprint = "0d77547064aeca6714ede98df686011c139ca720a71bcac23e40b0c02d302d6a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "4b2068a4a666b0279358b8eb4f480d2df4c518a8b4518d0d77c6687c3bff0a32"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { E0 03 48 89 45 A8 8B 45 BC 48 63 D0 48 83 EA 01 48 89 55 A0 48 }

	condition:
		all of them
}
