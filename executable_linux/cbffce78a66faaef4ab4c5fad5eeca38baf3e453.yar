rule Linux_Generic_Threat_9aaf894f
{
	meta:
		author = "Elastic Security"
		id = "9aaf894f-d3f0-460d-82f8-831fecdf8b09"
		fingerprint = "15518c7e99ed1f39db2fe21578c08aadf8553fdb9cb44e4342bf117e613c6c12"
		creation_date = "2024-01-22"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "467ac05956eec6c74217112721b3008186b2802af2cafed6d2038c79621bcb08"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 2F 62 69 6E 2F 63 70 20 2F 74 6D 70 2F 70 61 6E 77 74 65 73 74 20 2F 75 73 72 2F 62 69 6E 2F 70 73 }

	condition:
		all of them
}
