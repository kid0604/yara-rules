rule Windows_Generic_Threat_04a9c177
{
	meta:
		author = "Elastic Security"
		id = "04a9c177-cacf-4509-b8dc-f30a628b7699"
		fingerprint = "b36da73631711de0213658d30d3079f45449c303d8eb87b8342d1bd20120c7bb"
		creation_date = "2024-01-12"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "0cccdde4dcc8916fb6399c181722eb0da2775d86146ce3cb3fc7f8cf6cd67c29"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat based on specific fingerprint"
		filetype = "executable"

	strings:
		$a1 = { 6F 81 00 06 FE 3C A3 C3 D6 37 16 00 C2 87 21 EA 80 33 09 E5 00 2C 0F 24 BD 70 BC CB FB 00 94 5E 1B F8 14 F6 E6 95 07 01 CD 02 B0 D7 30 25 65 99 74 01 D6 A4 47 B3 20 AF 27 D8 11 7F 03 57 F6 37 }

	condition:
		all of them
}
