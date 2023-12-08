rule Linux_Trojan_Tsunami_32c0b950
{
	meta:
		author = "Elastic Security"
		id = "32c0b950-0636-42bb-bc67-1b727985625f"
		fingerprint = "e438287517c3492fa87115a3aa5402fd05f9745b7aed8e251fb3ed9d653984bb"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "214c1caf20ceae579476d3bf97f489484df4c5f1c0c44d37ff9b9066072cd83c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Trojan.Tsunami malware"
		filetype = "executable"

	strings:
		$a = { 05 20 BC F8 41 B8 20 07 09 20 35 15 11 03 20 85 }

	condition:
		all of them
}
