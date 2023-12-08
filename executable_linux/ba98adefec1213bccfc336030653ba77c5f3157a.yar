rule Linux_Trojan_Ddostf_e4874cd4
{
	meta:
		author = "Elastic Security"
		id = "e4874cd4-50e3-4a4c-b14c-976e29aaaaae"
		fingerprint = "dfbf7476794611718a1cd2c837560423e3a6c8b454a5d9eecb9c6f9d31d01889"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Ddostf"
		reference_sample = "1015b9aef1f749dfc31eb33528c4a4169035b6d73542e068b617965d3e948ef2"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Ddostf"
		filetype = "executable"

	strings:
		$a = { E4 01 8B 45 F0 2B 45 F4 89 C2 8B 45 E4 39 C2 73 82 8B 45 EC }

	condition:
		all of them
}
