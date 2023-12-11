rule Linux_Cryptominer_Pgminer_5fb2efd5
{
	meta:
		author = "Elastic Security"
		id = "5fb2efd5-4adc-4285-bef1-6e4987066944"
		fingerprint = "8ac56b60418e3f3f4d1f52c7a58d0b7c1f374611d45e560452c75a01c092a59b"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Pgminer"
		reference_sample = "6d296648fdbc693e604f6375eaf7e28b87a73b8405dc8cd3147663b5e8b96ff0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Pgminer malware"
		filetype = "executable"

	strings:
		$a = { 00 16 00 00 00 0E 00 00 00 18 03 00 7F EB 28 33 C5 56 5D F2 50 67 C5 6F }

	condition:
		all of them
}
