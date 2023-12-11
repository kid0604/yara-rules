rule Windows_Trojan_CobaltStrike_dcdcdd8c
{
	meta:
		author = "Elastic Security"
		id = "dcdcdd8c-7395-4453-a74a-60ab8e251a5a"
		fingerprint = "8aed1ae470d06a7aac37896df22b2f915c36845099839a85009212d9051f71e9"
		creation_date = "2021-10-21"
		last_modified = "2022-01-13"
		description = "Rule for beacon sleep PDB"
		threat_name = "Windows.Trojan.CobaltStrike"
		reference_sample = "36d32b1ed967f07a4bd19f5e671294d5359009c04835601f2cc40fb8b54f6a2a"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x64.o" ascii fullword
		$a2 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask.x86.o" ascii fullword
		$a3 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x64.o" ascii fullword
		$a4 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_smb.x86.o" ascii fullword
		$a5 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x64.o" ascii fullword
		$a6 = "Z:\\devcenter\\aggressor\\external\\sleepmask\\bin\\sleepmask_tcp.x86.o" ascii fullword

	condition:
		any of them
}
