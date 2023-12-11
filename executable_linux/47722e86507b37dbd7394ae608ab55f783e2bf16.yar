rule Linux_Cryptominer_Camelot_87639dbd
{
	meta:
		author = "Elastic Security"
		id = "87639dbd-da2d-4cf9-a058-16f4620a5a7f"
		fingerprint = "c145df0a671691ef2bf17644ec7c33ebb5826d330ffa35120d4ba9e0cb486282"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "d2d8421ffdcebb7fed00edcf306ec5e86fc30ad3e87d55e85b05bea5dc1f7d63"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot malware"
		filetype = "executable"

	strings:
		$a = { 45 00 48 83 C2 01 48 89 EF 48 89 53 38 FF 50 18 48 8D 7C 24 30 48 }

	condition:
		all of them
}
