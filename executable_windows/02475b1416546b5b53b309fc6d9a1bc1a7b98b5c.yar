rule Windows_Generic_Threat_df5de012
{
	meta:
		author = "Elastic Security"
		id = "df5de012-52b6-4558-a00b-2dbf052e34d3"
		fingerprint = "ee293cda37e0f1c76f89a7d1e074c9591950299b2ae87cca11c6cf7fbfee1fc4"
		creation_date = "2024-02-14"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "13c06d7b030a46c6bb6351f40184af9fafaf4c67b6a2627a45925dd17501d659"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 20 2C 3F 2C 2F 2C 37 2C 27 2C 3B 2C 2B 2C 33 2C 23 2C 3D 2C 2D 2C 35 2C 25 2C 39 2C 29 2C 31 2C 21 2C 3E 2C 2E 2C 36 2C 26 2C 3A 2C 2A 2C 32 2C 22 2C 3C 2C 2C 2C 34 2C 24 2C 38 2C 28 2C 30 2C 20 }

	condition:
		all of them
}
