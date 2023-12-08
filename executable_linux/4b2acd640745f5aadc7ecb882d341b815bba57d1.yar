rule Linux_Trojan_Mirai_e43a8744
{
	meta:
		author = "Elastic Security"
		id = "e43a8744-1c52-4f95-bd16-be6722bc4d1a"
		fingerprint = "e7ead3d1a51f0d7435a6964293a45cb8fadd739afb23dc48c1d81fbc593b23ef"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai with specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 23 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C }

	condition:
		all of them
}
