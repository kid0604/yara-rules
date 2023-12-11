rule MacOS_Trojan_Adload_4995469f
{
	meta:
		author = "Elastic Security"
		id = "4995469f-9810-4c1f-b9bc-97e951fe9256"
		fingerprint = "9b7e7c76177cc8ca727df5039a5748282f5914f2625ec1f54d67d444f92f0ee5"
		creation_date = "2021-10-04"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Adload"
		reference_sample = "6464ca7b36197cccf0dac00f21c43f0cb09f900006b1934e2b3667b367114de5"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Adload"
		filetype = "executable"

	strings:
		$a = { 49 8B 77 08 49 8B 4F 20 48 BF 89 88 88 88 88 88 88 88 48 89 C8 48 F7 E7 48 C1 }

	condition:
		all of them
}
