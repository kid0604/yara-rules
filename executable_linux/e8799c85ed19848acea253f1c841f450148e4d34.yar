rule Linux_Exploit_Dirtycow_8555f149
{
	meta:
		author = "Elastic Security"
		id = "8555f149-0c91-4384-9199-8250c0fd74fd"
		fingerprint = "3d607c7ba6667c375eaab454debf8745746230d08a00499395a275e5bd05b3e4"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Dirtycow"
		reference_sample = "0fd66e120f97100e48c65322b946b812fa9df4cfb533fb327760a999e4d43945"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the Linux.Exploit.Dirtycow vulnerability"
		filetype = "executable"

	strings:
		$a = { 83 45 F8 01 81 7D F8 FF E0 F5 05 7E ?? 8B 45 }

	condition:
		all of them
}
