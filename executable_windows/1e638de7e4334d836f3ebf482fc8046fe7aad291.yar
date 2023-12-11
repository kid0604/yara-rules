rule Windows_Ransomware_Haron_a1c12e7e
{
	meta:
		author = "Elastic Security"
		id = "a1c12e7e-a740-4d26-a0ed-310a2b03fe50"
		fingerprint = "c6abe96bd2848bb489f856373356dbad3fca273e9d71394ec22960070557ad11"
		creation_date = "2021-08-03"
		last_modified = "2021-10-04"
		description = "Direct overlap with Thanos/Avaddon"
		threat_name = "Windows.Ransomware.Haron"
		reference_sample = "6e6b78a1df17d6718daa857827a2a364b7627d9bfd6672406ad72b276014209c"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 00 04 28 0E 00 00 0A 06 FE 06 2A 00 00 06 73 0F 00 00 0A 28 }

	condition:
		any of them
}
