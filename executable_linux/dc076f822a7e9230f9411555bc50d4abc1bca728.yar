rule Linux_Cryptominer_Camelot_b25398dd
{
	meta:
		author = "Elastic Security"
		id = "b25398dd-33cc-4ad8-b943-cd06ff7811fb"
		fingerprint = "6bdcefe93b1c36848b79cdc6b2ff79deb04012a030e5d92e725c87e520c15554"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Camelot"
		reference_sample = "6fb3b77be0a66a10124a82f9ec6ad22247d7865a4d26aa49c5d602320318ce3c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Camelot"
		filetype = "executable"

	strings:
		$a = { 04 76 48 8B 44 07 23 48 33 82 C0 00 00 00 48 89 44 24 50 49 8B }

	condition:
		all of them
}
