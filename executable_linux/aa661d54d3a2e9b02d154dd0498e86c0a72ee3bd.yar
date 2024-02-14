rule Linux_Generic_Threat_0a02156c
{
	meta:
		author = "Elastic Security"
		id = "0a02156c-2958-44c5-9dbd-a70d528e507d"
		fingerprint = "aa7a34e72e03b70f2f73ae319e2cc9866fbf2eddd4e6a8a2835f9b7c400831cd"
		creation_date = "2024-02-01"
		last_modified = "2024-02-13"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "f23d4b1fd10e3cdd5499a12f426e72cdf0a098617e6b178401441f249836371e"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 72 65 71 75 69 72 65 73 5F 6E 75 6C 6C 5F 70 61 67 65 }
		$a2 = { 67 65 74 5F 65 78 70 6C 6F 69 74 5F 73 74 61 74 65 5F 70 74 72 }

	condition:
		all of them
}
