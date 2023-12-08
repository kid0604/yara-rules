rule Linux_Cryptominer_Camelot_4e7945a4
{
	meta:
		author = "Elastic Security"
		id = "4e7945a4-b827-4496-89d8-e63c3141c773"
		fingerprint = "bb2885705404c7d49491ab39fa8f50d85c354a43b4662b948c30635030feee74"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "b7504ce57787956e486d951b4ff78d73807fcc2a7958b172febc6d914e7a23a7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { 89 E5 48 81 EC A0 00 00 00 48 89 7D F0 48 8B 7D F0 48 89 F8 48 05 80 00 }

	condition:
		all of them
}
