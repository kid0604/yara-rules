rule Linux_Exploit_Vmsplice_8b9e4f9f
{
	meta:
		author = "Elastic Security"
		id = "8b9e4f9f-7903-4aa5-9098-766f4311a22b"
		fingerprint = "585b16ad3e4489a17610f0a226be428def33e411886f273d0c1db45b3819ba3f"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Vmsplice"
		reference_sample = "0230c81ba747e588cd9b6113df6e1867dcabf9d8ada0c1921d1bffa9c1b9c75d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Vmsplice threat"
		filetype = "executable"

	strings:
		$a = { 00 00 00 00 20 4C 69 6E 75 78 20 76 6D 73 70 6C }

	condition:
		all of them
}
