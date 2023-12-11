rule Linux_Cryptominer_Roboto_0b6807f8
{
	meta:
		author = "Elastic Security"
		id = "0b6807f8-49c1-485f-9233-1a14f98935bc"
		fingerprint = "65f373b6e820c2a1fa555182b8e4547bf5853326bdf3746c7592d018dc2ed89f"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Roboto"
		reference_sample = "c2542e399f865b5c490ee66b882f5ff246786b3f004abb7489ec433c11007dda"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Roboto malware"
		filetype = "executable"

	strings:
		$a = { FB 49 89 CF 4D 0F AF FC 4D 01 DF 4D 89 CB 4C 0F AF D8 4D 01 FB 4D }

	condition:
		all of them
}
