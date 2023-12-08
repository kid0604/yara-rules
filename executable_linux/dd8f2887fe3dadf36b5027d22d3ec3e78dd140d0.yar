rule Linux_Trojan_Tsunami_7c545abf
{
	meta:
		author = "Elastic Security"
		id = "7c545abf-822d-44bb-8ac9-1b7e4f27698d"
		fingerprint = "4141069d6c41c0c26b53a8a86fd675f09982ca6e99757a04ef95b9ad0b8efefa"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "95691c7ad1d80f7f1b5541e1d1a1dbeba30a26702a4080d256f14edb75851c5d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 03 FC DF 40 9C B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}
