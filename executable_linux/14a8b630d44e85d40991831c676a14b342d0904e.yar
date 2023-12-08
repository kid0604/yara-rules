rule Linux_Exploit_Foda_f41e9ef9
{
	meta:
		author = "Elastic Security"
		id = "f41e9ef9-b280-44cb-b877-ac998eea84d3"
		fingerprint = "d24064932ef3a972970ce446d465c28379bf83b1b72f5bf77d1def3074747a8e"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Foda"
		reference_sample = "6059a6dd039b5efa36ce97acbb01406128aaf6062429474e422624ee69783ca8"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Foda"
		filetype = "executable"

	strings:
		$a = { C0 50 89 E2 53 89 E1 B0 0B CD 80 31 C0 B0 01 CD }

	condition:
		all of them
}
