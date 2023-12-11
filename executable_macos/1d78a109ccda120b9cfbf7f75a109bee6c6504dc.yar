rule MacOS_Trojan_Bundlore_28b13e67
{
	meta:
		author = "Elastic Security"
		id = "28b13e67-e01c-45eb-aae6-ecd02b017a44"
		fingerprint = "1e85be4432b87214d61e675174f117e36baa8ab949701ee1d980ad5dd8454bac"
		creation_date = "2021-10-05"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Bundlore"
		reference_sample = "0b50a38749ea8faf571169ebcfce3dfd668eaefeb9a91d25a96e6b3881e4a3e8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS.Trojan.Bundlore malware"
		filetype = "executable"

	strings:
		$a = { 05 A5 A3 A9 37 D2 05 13 E9 3E D6 EA 6A EC 9B DC 36 E5 76 A7 53 B3 0F 06 46 D1 }

	condition:
		all of them
}
