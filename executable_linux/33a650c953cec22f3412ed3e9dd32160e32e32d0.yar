rule Linux_Trojan_Tsunami_e98b83ee
{
	meta:
		author = "Elastic Security"
		id = "e98b83ee-0533-481a-9947-538bd2f99b6b"
		fingerprint = "b5440c783bc18e23f27a3131ccce4629f8d0ceea031971cbcdb69370ab52e935"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "cf1ca1d824c8687e87a5b0275a0e39fa101442b4bbf470859ddda9982f9b3417"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 45 FE 00 00 EB 16 48 8B 55 D8 0F B7 02 0F B7 C0 01 45 E0 48 83 45 }

	condition:
		all of them
}
