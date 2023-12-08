rule Windows_Trojan_Generic_a681f24a
{
	meta:
		author = "Elastic Security"
		id = "a681f24a-7054-4525-bcf8-3ee64a1d8413"
		fingerprint = "6323ed5b60e728297de19c878cd96b429bfd6d82157b4cf3475f3a3123921ae0"
		creation_date = "2021-06-10"
		last_modified = "2021-08-23"
		threat_name = "Windows.Trojan.Generic"
		reference_sample = "a796f316b1ed7fa809d9ad5e9b25bd780db76001345ea83f5035a33618f927fa"
		severity = 25
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Generic"
		filetype = "executable"

	strings:
		$a = "_kasssperskdy" wide fullword
		$b = "[Time:]%d-%d-%d %d:%d:%d" wide fullword
		$c = "{SDTB8HQ9-96HV-S78H-Z3GI-J7UCTY784HHC}" wide fullword

	condition:
		2 of them
}
