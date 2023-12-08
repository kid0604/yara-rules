rule Linux_Exploit_Cornelgen_584a227a
{
	meta:
		author = "Elastic Security"
		id = "584a227a-bf17-4620-8b10-97676f12ea5b"
		fingerprint = "65a23e20166b99544b2d0b4969240618d50e80a53a69829756721e19e4e6899f"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Cornelgen"
		reference_sample = "c823cb669f1d6cb9258d6f0b187609c226af23396f9c5be26eb479e5722a9d97"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Cornelgen malware"
		filetype = "executable"

	strings:
		$a = { 6E 89 E3 52 53 89 E1 B0 0B CD 80 31 C0 40 CD 80 }

	condition:
		all of them
}
