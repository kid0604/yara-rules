rule Linux_Trojan_Gafgyt_9c18716c
{
	meta:
		author = "Elastic Security"
		id = "9c18716c-e5cd-4b4f-98e2-0daed77f34cd"
		fingerprint = "351772d2936ec1a14ee7e2f2b79a8fde62d02097ae6a5304c67e00ad1b11085a"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Gafgyt"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Gafgyt variant with fingerprint 9c18716c"
		filetype = "executable"

	strings:
		$a = { FC 80 F6 FE 59 21 EC 75 10 26 CF DC 7B 5A 5B 4D 24 C9 C0 F3 }

	condition:
		all of them
}
