rule Linux_Shellcode_Generic_5669055f
{
	meta:
		author = "Elastic Security"
		id = "5669055f-8ce7-4163-af06-cb265fde3eef"
		fingerprint = "616fe440ff330a1d22cacbdc2592c99328ea028700447724d2d5b930554a22f4"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "87ef4def16d956cdfecaea899cbb55ff59a6739bbb438bf44a8b5fec7fcfd85b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "executable"

	strings:
		$a = { 00 31 C0 31 DB 31 C9 B0 17 CD 80 31 C0 51 B1 06 }

	condition:
		all of them
}
