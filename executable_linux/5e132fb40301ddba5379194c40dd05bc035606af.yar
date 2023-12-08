rule Linux_Trojan_Gafgyt_148b91a2
{
	meta:
		author = "Elastic Security"
		id = "148b91a2-ed51-4c2d-9d15-6a48d9ea3e0a"
		fingerprint = "0f75090ed840f4601df4e43a2f49f2b32585213f3d86d19fb255d79c21086ba3"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		reference_sample = "d5b2bde0749ff482dc2389971e2ac76c4b1e7b887208a538d5555f0fe6984825"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with ID 148b91a2"
		filetype = "executable"

	strings:
		$a = { C6 45 DB FC EB 04 C6 45 DB FE 0F B6 45 DB 88 45 FF 48 8D 75 FF 8B }

	condition:
		all of them
}
