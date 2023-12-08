rule Linux_Hacktool_Flooder_c680c9fd
{
	meta:
		author = "Elastic Security"
		id = "c680c9fd-34ad-4d92-b8d6-1b511c7c07a3"
		fingerprint = "5cb5b36d3ae5525b992a9d395b54429f52b11ea229e0cecbd62317af7b5faf84"
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
		$a = { 45 A0 8B 55 CC 48 63 D2 48 C1 E2 05 48 01 D0 48 8D 48 10 48 8B }

	condition:
		all of them
}
