rule MacOS_Trojan_Adload_9b9f86c7
{
	meta:
		author = "Elastic Security"
		id = "9b9f86c7-e74c-4fc2-bb64-f87473a4b820"
		fingerprint = "7e70d5574907261e73d746a4ad0b7bce319a9bb3b39a7f1df326284960a7fa38"
		creation_date = "2021-10-04"
		last_modified = "2021-10-25"
		threat_name = "MacOS.Trojan.Adload"
		reference_sample = "952e6004ce164ba607ac7fddc1df3d0d6cac07d271d90be02d790c52e49cb73c"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "macos"
		description = "Detects MacOS Trojan Adload variant 9b9f86c7"
		filetype = "executable"

	strings:
		$a = { 44 65 6C 65 67 61 74 65 43 35 73 68 6F 77 6E 53 62 76 70 57 76 64 }

	condition:
		all of them
}
