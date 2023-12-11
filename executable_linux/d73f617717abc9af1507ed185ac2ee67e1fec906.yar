rule Linux_Exploit_CVE_2017_16995_82816caa
{
	meta:
		author = "Elastic Security"
		id = "82816caa-2fff-4b71-9544-443e611aacbf"
		fingerprint = "1a716566946fdd368230c02e2c749b6ce371fa6211be6b3db137af9b117bec87"
		creation_date = "2022-01-05"
		last_modified = "2022-01-26"
		threat_name = "Linux.Exploit.CVE-2017-16995"
		reference_sample = "14e6b788db0db57067d9885ab5ff3d3a5749639549d82abd98fa4fcf27000f34"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2017-16995"
		filetype = "executable"

	strings:
		$a = { BC 89 45 C0 8B 45 B8 48 98 48 C1 E8 03 89 45 C4 48 8B 45 B0 48 }

	condition:
		all of them
}
