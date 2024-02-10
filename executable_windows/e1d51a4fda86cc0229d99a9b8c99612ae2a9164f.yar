rule Windows_Generic_Threat_7a49053e
{
	meta:
		author = "Elastic Security"
		id = "7a49053e-5ae4-4141-9471-4a92e0ee226e"
		fingerprint = "49c41c5372da04b770d903013ee7f71193a4650340fd4245d6d5bceff674d637"
		creation_date = "2024-01-29"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "29fb2b18cfd72a2966640ff59e67c89f93f83fc17afad2dfcacf9f53e9ea3446"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 5D 76 3F 3F 32 40 59 41 50 41 58 49 40 5A 66 }
		$a2 = { 41 75 74 68 6F 72 69 7A 61 26 42 61 73 69 63 48 24 }
		$a3 = { 4A 7E 4C 65 61 76 65 47 65 74 51 75 65 }

	condition:
		all of them
}
