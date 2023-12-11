rule Linux_Worm_Generic_920d273f
{
	meta:
		author = "Elastic Security"
		id = "920d273f-5b2b-4eec-a2b3-8d411f2ea181"
		fingerprint = "3d4dd13b715249710bc2a02b1628fb68bcccebab876ff6674cad713e93ac53d2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Worm.Generic"
		reference_sample = "04a65bc73fab91f654d448b2d7f8f15ac782965dcdeec586e20b5c7a8cc42d73"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Worm.Generic based on specific fingerprint"
		filetype = "executable"

	strings:
		$a = { E9 E5 49 86 49 A4 1A 70 C7 A4 AD 2E E9 D9 09 F5 AD CB ED FC 3B }

	condition:
		all of them
}
