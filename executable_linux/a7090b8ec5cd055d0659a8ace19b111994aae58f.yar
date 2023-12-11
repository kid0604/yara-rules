rule Linux_Trojan_Xhide_7f0a131b
{
	meta:
		author = "Elastic Security"
		id = "7f0a131b-c305-4a08-91cc-ac2de4d95b19"
		fingerprint = "767f2ea258cccc9f9b6673219d83e74da1d59f6847161791c9be04845f17d8cb"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Xhide"
		reference_sample = "0dc35f1a1fe1c59e454cd5645f3a6220b7d85661437253a3e627eed04eca2560"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Xhide (7f0a131b)"
		filetype = "executable"

	strings:
		$a = { 8B 85 68 FF FF FF 83 E0 40 85 C0 75 1A 8B 85 68 FF FF FF 83 }

	condition:
		all of them
}
