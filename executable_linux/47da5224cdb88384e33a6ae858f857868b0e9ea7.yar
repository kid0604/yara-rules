rule Linux_Cryptominer_Roboto_1f1cfe9a
{
	meta:
		author = "Elastic Security"
		id = "1f1cfe9a-ab4a-423c-a62b-ead6901e2a86"
		fingerprint = "8dd9f4a091713b8992abd97474f66fdc7d34b0124f06022ab82942f88f3b330c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Roboto"
		reference_sample = "497a6d426ff93d5cd18cea623074fb209d4f407a02ef8f382f089f1ed3f108c5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Roboto malware"
		filetype = "executable"

	strings:
		$a = { 24 20 85 FF 74 0D 39 FE 73 13 83 FE 0F 77 0E 01 F6 EB F3 BF 01 00 }

	condition:
		all of them
}
