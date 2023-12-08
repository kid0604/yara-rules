rule Linux_Cryptominer_Malxmr_12299814
{
	meta:
		author = "Elastic Security"
		id = "12299814-c916-4cad-a627-f8b082f5643d"
		fingerprint = "b626f04a8648b0f42564df9c2ef3989e602d1307b18256e028450c495dc15260"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Malxmr"
		reference_sample = "eb3802496bd2fef72bd2a07e32ea753f69f1c2cc0b5a605e480f3bbb80b22676"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Malxmr malware"
		filetype = "executable"

	strings:
		$a = { 3C 40 00 83 C4 10 89 44 24 04 80 7D 00 00 74 97 83 EC 0C 89 }

	condition:
		all of them
}
