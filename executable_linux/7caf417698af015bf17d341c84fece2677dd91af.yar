rule Linux_Trojan_Mirai_4e2246fb
{
	meta:
		author = "Elastic Security"
		id = "4e2246fb-5f9a-4dea-8041-51758920d0b9"
		fingerprint = "23b0cfabc2db26153c02a7dc81e2006b28bfc9667526185b2071b34d2fb073c4"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Trojan.Mirai"
		reference_sample = "1f6bcdfc7d1c56228897cd7548266bb0b9a41b913be354036816643ac21b6f66"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Mirai variant with fingerprint 4e2246fb"
		filetype = "executable"

	strings:
		$a = { 00 00 B8 01 00 00 00 31 DB CD 80 EB FA 8D 8B 10 }

	condition:
		all of them
}
