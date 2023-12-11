rule Linux_Trojan_Generic_8ca4b663
{
	meta:
		author = "Elastic Security"
		id = "8ca4b663-b282-4322-833a-4c0143f63634"
		fingerprint = "34e04e32ee493643cc37ff0cfb94dcbc91202f651bc2560e9c259b53a9d6acfc"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "1ddf479e504867dfa27a2f23809e6255089fa0e2e7dcf31b6ce7d08f8d88947e"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects a generic Linux Trojan"
		filetype = "executable"

	strings:
		$a = { 28 60 DF F2 FB B7 E7 EB 96 D1 E6 96 88 12 96 EB 8C 94 EB C7 4E }

	condition:
		all of them
}
