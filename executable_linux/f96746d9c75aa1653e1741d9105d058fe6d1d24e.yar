rule Linux_Trojan_Gafgyt_a473dcb6
{
	meta:
		author = "Elastic Security"
		id = "a473dcb6-887e-4a9a-a1f2-df094f1575b9"
		fingerprint = "6119a43aa5c9f61249083290293f15696b54b012cdf92553fd49736d40c433f9"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "7ba74e3cb0d633de0e8dbe6cfc49d4fc77dd0c02a5f1867cc4a1f1d575def97d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux Trojan Gafgyt"
		filetype = "executable"

	strings:
		$a = { 49 56 04 0B 1E 46 1E B0 EB 10 18 38 38 D7 80 4D 2D 03 29 62 }

	condition:
		all of them
}
