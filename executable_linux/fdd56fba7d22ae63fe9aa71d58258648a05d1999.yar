rule Linux_Trojan_Generic_4675dffa
{
	meta:
		author = "Elastic Security"
		id = "4675dffa-0536-4a4d-bedb-f8c7fa076168"
		fingerprint = "7aa556e481694679ce0065bcaaa4d35e2c2382326681f03202b68b1634db08ab"
		creation_date = "2023-07-28"
		last_modified = "2024-02-13"
		threat_name = "Linux.Trojan.Generic"
		reference_sample = "43e14c9713b1ca1f3a7f4bcb57dd3959d3a964be5121eb5aba312de41e2fb7a6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux Trojan Generic"
		filetype = "executable"

	strings:
		$a1 = ", i = , not , val ./zzzz.local.onion"
		$a2 = { 61 74 20 20 25 76 3D 25 76 2C 20 28 63 6F 6E 6E 29 20 28 73 63 61 6E 20 20 28 73 63 }

	condition:
		all of them
}
