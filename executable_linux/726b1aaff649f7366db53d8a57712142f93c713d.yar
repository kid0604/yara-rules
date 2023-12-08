rule Linux_Cryptominer_Xmrminer_70c153b5
{
	meta:
		author = "Elastic Security"
		id = "70c153b5-2628-4504-8f21-2c7f0201b133"
		fingerprint = "51d304812e72045387b002824fdc9231d64bf4e8437c70150625c4b2aa292284"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Cryptominer.Xmrminer"
		reference_sample = "55b133ba805bb691dc27a5d16d3473650360c988e48af8adc017377eed07935b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Cryptominer.Xmrminer malware"
		filetype = "executable"

	strings:
		$a = { EC 18 BA 08 00 00 00 48 8D 4C 24 08 48 89 74 24 08 BE 02 00 }

	condition:
		all of them
}
