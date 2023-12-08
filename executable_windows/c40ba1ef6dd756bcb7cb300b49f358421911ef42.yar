rule Windows_Trojan_IcedID_0b62e783
{
	meta:
		author = "Elastic Security"
		id = "0b62e783-5c1a-4377-8338-1c53194b8d01"
		fingerprint = "2f473fbe6338d9663808f1a3615cf8f0f6f9780fbce8f4a3c24f0ddc5f43dd4a"
		creation_date = "2022-04-06"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.IcedID"
		reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID variant 0b62e783"
		filetype = "executable"

	strings:
		$a = { 89 44 95 E0 83 E0 07 8A C8 42 8B 44 85 E0 D3 C8 FF C0 42 89 44 }

	condition:
		all of them
}
