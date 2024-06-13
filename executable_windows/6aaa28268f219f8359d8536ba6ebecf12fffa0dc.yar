rule Windows_Generic_Threat_2bba6bae
{
	meta:
		author = "Elastic Security"
		id = "2bba6bae-7c6a-4b89-83d8-0656d7863820"
		fingerprint = "85dc02cb74c481b5ecb144280827add9665138f0b5d479db5468a94b41e662a3"
		creation_date = "2024-03-05"
		last_modified = "2024-06-12"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "d9955c716371422750b77d64256dade6fbd028c8d965db05c0d889d953480373"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 36 35 20 37 39 20 34 31 20 36 39 20 36 34 20 34 38 20 36 43 20 37 37 20 34 39 20 36 41 20 36 46 20 36 37 20 34 39 20 36 42 20 37 30 20 35 38 20 35 36 20 34 33 20 34 39 20 37 33 20 34 39 20 34 33 20 34 41 20 36 38 20 36 32 20 34 37 20 36 33 20 36 39 20 34 46 20 36 39 20 34 31 20 36 39 20 35 32 20 35 37 20 35 32 20 34 35 20 35 35 20 33 30 20 34 35 20 36 39 20 34 39 20 34 38 20 33 30 }

	condition:
		all of them
}
