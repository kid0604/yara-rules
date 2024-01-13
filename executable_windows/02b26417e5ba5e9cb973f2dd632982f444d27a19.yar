rule Windows_Trojan_AgentTesla_ebf431a8
{
	meta:
		author = "Elastic Security"
		id = "ebf431a8-45e8-416c-a355-4ac1db2d133a"
		fingerprint = "2d95dbe502421d862eee33ba819b41cb39cf77a44289f4de4a506cad22f3fddb"
		creation_date = "2023-12-01"
		last_modified = "2024-01-12"
		threat_name = "Windows.Trojan.AgentTesla"
		reference_sample = "0cb3051a80a0515ce715b71fdf64abebfb8c71b9814903cb9abcf16c0403f62b"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan AgentTesla variant with specific strings"
		filetype = "executable"

	strings:
		$a1 = "MozillaBrowserList"
		$a2 = "EnableScreenLogger"
		$a3 = "VaultGetItem_WIN7"
		$a4 = "PublicIpAddressGrab"
		$a5 = "EnableTorPanel"
		$a6 = "get_GuidMasterKey"

	condition:
		4 of them
}
