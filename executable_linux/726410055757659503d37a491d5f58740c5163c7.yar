rule Linux_Trojan_Swrort_5ad1a4f9
{
	meta:
		author = "Elastic Security"
		id = "5ad1a4f9-bfe5-4e5f-94e9-4983c93a1c1f"
		fingerprint = "a91458dd4bcd082506c554ca8479e1b0d23598e0e9a0e44ae1afb2651ce38dce"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Swrort"
		reference_sample = "fa5695c355a6dc1f368a4b36a45e8f18958dacdbe0eac80c618fbec976bac8fe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Swrort"
		filetype = "executable"

	strings:
		$a = { 53 57 68 B7 E9 38 FF FF D5 53 53 57 68 74 EC 3B E1 FF D5 57 }

	condition:
		all of them
}
