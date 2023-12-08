rule Windows_Trojan_IcedID_48029e37
{
	meta:
		author = "Elastic Security"
		id = "48029e37-b392-4d53-b0de-2079f6a8a9d9"
		fingerprint = "375266b526fe14354550d000d3a10dde3f6a85e11f4ba5cab14d9e1f878de51e"
		creation_date = "2022-04-06"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.IcedID"
		reference_sample = "b9fb0a4c28613c556fb67a0b0e7c9d4c1236b60a161ad935e7387aec5911413a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan IcedID"
		filetype = "executable"

	strings:
		$a = { 48 C1 E3 10 0F 31 48 C1 E2 ?? 48 0B C2 0F B7 C8 48 0B D9 8B CB 83 E1 }

	condition:
		all of them
}
