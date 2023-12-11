rule Linux_Trojan_Mirai_ea584243
{
	meta:
		author = "Elastic Security"
		id = "ea584243-6ead-4b96-9a5c-5b5dee12fd57"
		fingerprint = "cbcabf4cba48152b3599570ef84503bfb8486db022a2b10df7544d4384023355"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "f363d9bd2132d969cd41e79f29c53ef403da64ca8afc4643084cc50076ddfb47"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai based on specific fingerprint"
		filetype = "executable"

	strings:
		$a = { 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D 04 9A 3C 81 FA }

	condition:
		all of them
}
