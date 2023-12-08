rule Linux_Exploit_Vmsplice_a000f267
{
	meta:
		author = "Elastic Security"
		id = "a000f267-b4d7-46e9-ab61-818633083ba2"
		fingerprint = "0753ef1bc3e151fd6d4773967b5cde6ad789df593e7d8b9ed08052151a1a1849"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Vmsplice"
		reference_sample = "c85cc6768a28fb7de16f1cad8d3c69d8f0b4aa01e00c8e48759d27092747ca6f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Vmsplice vulnerability"
		filetype = "executable"

	strings:
		$a = { 24 04 73 00 00 00 89 44 24 00 CF 83 C4 10 5B C9 C3 55 89 E5 83 }

	condition:
		all of them
}
