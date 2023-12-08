rule Linux_Trojan_Gafgyt_fbed4652
{
	meta:
		author = "Elastic Security"
		id = "fbed4652-2c68-45c6-8116-e3fe7d0a28b8"
		fingerprint = "a08bcc7d0999562b4ef2d8e0bdcfa111fe0f76fc0d3b14d42c8e93b7b90abdca"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "2ea21358205612f5dc0d5f417c498b236c070509531621650b8c215c98c49467"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 02 00 00 2B 01 00 00 0E 00 00 00 18 03 00 7F E9 38 32 C9 4D }

	condition:
		all of them
}
