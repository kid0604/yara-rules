rule Linux_Trojan_Tsunami_c94eec37
{
	meta:
		author = "Elastic Security"
		id = "c94eec37-8ae1-48d2-8c75-36f2582a2742"
		fingerprint = "c692073af446327f739e1c81f4e3b56d812c00c556e882fe77bfdff522082db4"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Tsunami"
		reference_sample = "294fcdd57fc0a53e2d63b620e85fa65c00942db2163921719d052d341aa2dc30"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Tsunami"
		filetype = "executable"

	strings:
		$a = { 05 88 10 8B 45 E4 0F B6 10 83 E2 0F 83 CA 40 88 10 8B 45 E4 C6 40 }

	condition:
		all of them
}
