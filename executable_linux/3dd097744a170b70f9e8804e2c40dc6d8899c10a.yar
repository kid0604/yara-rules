rule Linux_Hacktool_Flooder_cce8c792
{
	meta:
		author = "Elastic Security"
		id = "cce8c792-ef3e-43c2-b4ad-343de6a69cc7"
		fingerprint = "03541eb8a293e88c0b8e6509310f8c57f2cd16b5ff76783a73bde2b614b607fc"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Hacktool.Flooder"
		reference_sample = "ea56da9584fc36dc67cb1e746bd13c95c4d878f9d594e33221baad7e01571ee6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Hacktool.Flooder"
		filetype = "executable"

	strings:
		$a = { 01 48 89 51 08 48 8B 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 }

	condition:
		all of them
}
