rule Windows_Generic_Threat_a3d51e0c
{
	meta:
		author = "Elastic Security"
		id = "a3d51e0c-9d49-48e5-abdb-ceeb10780cfa"
		fingerprint = "069a218c752b5aac5b26b19b36b641b3dd31f09d7fcaae735efb52082a3495cc"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "18bd25df1025cd04b0642e507b0170bc1a2afba71b2dc4bd5e83cc487860db0d"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 53 56 8B 75 08 33 DB 39 5D 14 57 75 10 3B F3 75 10 39 5D 0C 75 12 33 C0 5F 5E 5B 5D C3 3B F3 74 07 8B 7D 0C 3B FB 77 1B E8 05 F8 FF FF 6A 16 5E 89 30 53 53 53 53 53 E8 97 F7 FF FF 83 }

	condition:
		all of them
}
