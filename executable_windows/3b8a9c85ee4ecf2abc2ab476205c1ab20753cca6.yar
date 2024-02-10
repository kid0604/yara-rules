rule Windows_Generic_Threat_9c7d2333
{
	meta:
		author = "Elastic Security"
		id = "9c7d2333-f2c4-4d90-95ce-d817da5cb2a3"
		fingerprint = "3f003cc34b797887b5bbfeb729441d7fdb537d4516f13b215e1f6eceb5a8afaf"
		creation_date = "2024-01-17"
		last_modified = "2024-02-08"
		threat_name = "Windows.Generic.Threat"
		reference_sample = "85219f1402c88ab1e69aa99fe4bed75b2ad1918f4e95c448cdc6a4b9d2f9a5d4"
		severity = 50
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic threat"
		filetype = "executable"

	strings:
		$a1 = { 55 8B EC 81 EC 64 09 00 00 57 C6 85 00 F8 FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 F8 FF FF F3 AB 66 AB AA C6 85 00 FC FF FF 00 B9 FF 00 00 00 33 C0 8D BD 01 FC FF FF F3 AB 66 AB AA C7 85 AC F6 }

	condition:
		all of them
}
