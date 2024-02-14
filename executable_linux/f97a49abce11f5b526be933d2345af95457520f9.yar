rule Linux_Ransomware_EchoRaix_ee0c719a
{
	meta:
		author = "Elastic Security"
		id = "ee0c719a-1f04-45ff-9e49-38028b138fd0"
		fingerprint = "073d62ce55b1940774ffadeb5b76343aa49bd0a36cf82d50e2bae44f6049a1e8"
		creation_date = "2023-07-29"
		last_modified = "2024-02-13"
		threat_name = "Linux.Ransomware.EchoRaix"
		reference_sample = "e711b2d9323582aa390cf34846a2064457ae065c7d2ee1a78f5ed0859b40f9c0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Ransomware.EchoRaix malware"
		filetype = "executable"

	strings:
		$a1 = { 24 10 89 44 24 68 8B 4C 24 14 8B 54 24 18 85 C9 74 57 74 03 8B }
		$a2 = { 6D 61 69 6E 2E 43 68 65 63 6B 49 73 52 75 6E 6E 69 6E 67 }

	condition:
		all of them
}
