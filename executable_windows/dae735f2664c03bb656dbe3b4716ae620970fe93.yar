rule Windows_Generic_Threat_2c80562d
{
	meta:
		author = "Elastic Security"
		id = "2c80562d-2377-43b2-864f-0f122530b85d"
		fingerprint = "30965c0d6ac30cfb10674b2600e5a1e7b14380072738dd7993bd3eb57c825f24"
		creation_date = "2024-01-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "ee8decf1e8e5a927e3a6c10e88093bb4b7708c3fd542d98d43f1a882c6b0198e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 50 6F 6C 79 6D 6F 64 58 54 2E 65 78 65 }
		$a2 = { 50 6F 6C 79 6D 6F 64 58 54 20 76 31 2E 33 }
		$a3 = { 50 6F 6C 79 6D 6F 64 20 49 6E 63 2E }

	condition:
		all of them
}
