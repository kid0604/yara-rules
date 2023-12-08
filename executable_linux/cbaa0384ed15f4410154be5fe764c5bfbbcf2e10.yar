rule Linux_Cryptominer_Uwamson_d08b1d2e
{
	meta:
		author = "Elastic Security"
		id = "d08b1d2e-cbd5-420e-8f36-22b9efb5f12c"
		fingerprint = "1e55dc81a44af9c15b7a803e72681b5c24030d34705219f83ca4779fd885098c"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Uwamson"
		reference_sample = "4f7ad24b53b8e255710e4080d55f797564aa8c270bf100129bdbe52a29906b78"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Uwamson malware"
		filetype = "executable"

	strings:
		$a = { 4F F8 49 8D 7D 18 89 D9 49 83 C5 20 48 89 FE 41 83 E1 0F 4D 0F }

	condition:
		all of them
}
