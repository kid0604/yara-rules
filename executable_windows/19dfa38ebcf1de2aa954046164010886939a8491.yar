rule Windows_Trojan_RedLineStealer_d25e974b
{
	meta:
		author = "Elastic Security"
		id = "d25e974b-7cf0-4c0e-bf57-056cbb90d77e"
		fingerprint = "f936511802dcce39dfed9ec898f3ab0c4b822fd38bac4e84d60966c7b791688c"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.RedLineStealer"
		reference_sample = "a91c1d3965f11509d1c1125210166b824a79650f29ea203983fffb5f8900858c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan RedLineStealer"
		filetype = "executable"

	strings:
		$a = { 48 43 3F FF 48 42 3F FF 48 42 3F FF 48 42 3E FF 48 42 3E FF }

	condition:
		all of them
}
