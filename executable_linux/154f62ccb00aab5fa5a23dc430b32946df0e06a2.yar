rule Linux_Generic_Threat_898d9308
{
	meta:
		author = "Elastic Security"
		id = "898d9308-86d1-4b73-ae6c-c24716466f60"
		fingerprint = "fe860a6283aff8581b73440f9afbd807bb03b86dd9387b0b4ee5842a39ed7b03"
		creation_date = "2024-01-18"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "ce89863a16787a6f39c25fd15ee48c4d196223668a264217f5d1cea31f8dc8ef"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 65 63 66 61 66 65 61 62 36 65 65 37 64 36 34 32 }
		$a2 = { 3D 3D 3D 3D 65 6E 64 20 64 75 6D 70 20 70 6C 75 67 69 6E 20 69 6E 66 6F 3D 3D 3D 3D }

	condition:
		all of them
}
