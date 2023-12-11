rule MacOS_Trojan_Bundlore_7b9f0c28
{
	meta:
		author = "Elastic Security"
		id = "7b9f0c28-181d-4fdc-8a57-467d5105129a"
		fingerprint = "dde16fdd37a16fa4dae24324283cd4b36ed2eb78f486cedd1a6c7bef7cde7370"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "fc4da125fed359d3e1740dafaa06f4db1ffc91dbf22fd5e7993acf8597c4c283"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Bundlore variant 7b9f0c28"
		filetype = "executable"

	strings:
		$a = { 35 B6 15 00 00 81 80 35 B0 15 00 00 14 80 35 AA 15 00 00 BC 80 35 A4 15 00 00 }

	condition:
		all of them
}
