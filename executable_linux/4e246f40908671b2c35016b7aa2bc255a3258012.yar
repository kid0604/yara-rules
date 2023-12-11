rule Linux_Trojan_Ladvix_c9888edb
{
	meta:
		author = "Elastic Security"
		id = "c9888edb-0f82-4c7a-b501-4e4d3c9c64e3"
		fingerprint = "e0e0d75a6de7a11b2391f4a8610a6d7c385df64d43fa1741d7fe14b279e1a29a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ladvix"
		reference_sample = "1d798e9f15645de89d73e2c9d142189d2eaf81f94ecf247876b0b865be081dca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ladvix"
		filetype = "executable"

	strings:
		$a = { E8 01 83 45 E4 01 8B 45 E4 83 F8 57 76 B5 83 45 EC 01 8B 45 EC 48 }

	condition:
		all of them
}
