rule Linux_Shellcode_Generic_8ac37612
{
	meta:
		author = "Elastic Security"
		id = "8ac37612-aec8-4376-8269-2594152ced8a"
		fingerprint = "97a3d3e7ff4c9ae31f71e609d10b3b848cb0390ae2d1d738ef53fd23ff0621bc"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "c199b902fa4b0fcf54dc6bf3e25ad16c12f862b47e055863a5e9e1f98c6bd6ca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "script"

	strings:
		$a = { 89 E3 ?? 53 89 E1 B0 0B CD 80 00 47 43 43 3A }

	condition:
		all of them
}
