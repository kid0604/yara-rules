rule Linux_Exploit_Enoket_80fac3e9
{
	meta:
		author = "Elastic Security"
		id = "80fac3e9-bf77-46d1-8d9b-25f3cf06a3b7"
		fingerprint = "627418bfe84af36e9b34d42aa42cb6d793e6bc41aa555a77e4f9389a9407d6f2"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Enoket"
		reference_sample = "3355ad81c566914a7d7734b40c46ded0cfa53aa22c6e834d42e185bf8bbe6128"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux.Exploit.Enoket"
		filetype = "executable"

	strings:
		$a = { 42 4C 45 20 54 4F 20 4D 41 50 20 5A 45 52 4F 20 50 41 47 45 }

	condition:
		all of them
}
