rule MacOS_Trojan_Bundlore_00d9d0e9
{
	meta:
		author = "Elastic Security"
		id = "00d9d0e9-28d8-4c32-bc6f-52008ee69b07"
		fingerprint = "7dcc6b124d631767c259101f36b4bbd6b9d27b2da474d90e31447ea03a2711a6"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "73069b34e513ff1b742b03fed427dc947c22681f30cf46288a08ca545fc7d7dd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Bundlore malware"
		filetype = "executable"

	strings:
		$a = { 35 8E 11 00 00 55 80 35 88 11 00 00 BC 80 35 82 11 00 00 72 80 35 7C 11 00 00 }

	condition:
		all of them
}
