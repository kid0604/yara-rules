rule Linux_Trojan_Ladvix_77d184fd
{
	meta:
		author = "Elastic Security"
		id = "77d184fd-a15e-40e5-ac7e-0d914cc009fe"
		fingerprint = "21361ca7c26c98903626d1167747c6fd11a5ae0d6298d2ef86430ce5be0ecd1a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ladvix"
		reference_sample = "1bb44b567b3c82f7ee0e08b16f7326d1af57efe77d608a96b2df43aab5faa9f7"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ladvix"
		filetype = "executable"

	strings:
		$a = { 40 10 48 89 45 80 8B 85 64 FF FF FF 48 89 E2 48 89 D3 48 63 D0 48 83 }

	condition:
		all of them
}
