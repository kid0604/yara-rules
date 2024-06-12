rule Linux_Trojan_Mettle_e8fdbcbd
{
	meta:
		author = "Elastic Security"
		id = "e8fdbcbd-84d3-4c42-986b-c8d5d940a96a"
		fingerprint = "2038686308a77286ed5d13b408962075933da7ca5772d46b65e5f247193036b5"
		creation_date = "2024-05-06"
		last_modified = "2024-05-21"
		threat_name = "Linux.Trojan.Mettle"
		reference_sample = "864eae4f27648b8a9d9b0eb1894169aa739311cdd02b1435a34881acf7059d58"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Mettle malware"
		filetype = "executable"

	strings:
		$mettle1 = "mettlesploit!"
		$mettle2 = "/mettle/mettle/src/"
		$mettle3 = "mettle_get_c2"
		$mettle4 = "mettle_console_start_interactive"
		$mettle5 = "mettle_get_machine_id"

	condition:
		2 of ($mettle*)
}
