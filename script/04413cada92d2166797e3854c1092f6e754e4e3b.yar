rule Linux_Shellcode_Generic_d2c96b1d
{
	meta:
		author = "Elastic Security"
		id = "d2c96b1d-f424-476c-9463-dd34a1da524e"
		fingerprint = "ee042895d863310ff493fdd33721571edd322e764a735381d236b2c0a7077cfa"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "403d53a65bd77856f7c565307af5003b07413f2aba50869655cdd88ce15b0c82"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "script"

	strings:
		$a = { 89 E1 8D 54 24 04 5B B0 0B CD 80 31 C0 B0 01 31 }

	condition:
		all of them
}
