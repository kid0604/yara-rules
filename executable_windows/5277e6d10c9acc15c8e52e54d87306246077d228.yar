rule Windows_Trojan_CobaltStrike_8ee55ee5
{
	meta:
		author = "Elastic Security"
		id = "8ee55ee5-67f1-4f94-ab93-62bb5cfbeee9"
		fingerprint = "7e7ed4f00d0914ce0b9f77b6362742a9c8b93a16a6b2a62b70f0f7e15ba3a72b"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for wmi exec module"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x64.o" ascii fullword
		$a2 = "z:\\devcenter\\aggressor\\external\\pxlib\\bin\\wmiexec.x86.o" ascii fullword

	condition:
		1 of ($a*)
}
