rule Windows_Trojan_Rhadamanthys_21b60705
{
	meta:
		author = "Elastic Security"
		id = "21b60705-9696-43ba-a820-d8ab9c34cca2"
		fingerprint = "8a756bf4a8c9402072531aca2c29a382881c1808a790432ccac2240b35c09383"
		creation_date = "2023-03-19"
		last_modified = "2023-04-23"
		threat_name = "Windows.Trojan.Rhadamanthys"
		reference_sample = "3ba97c51ba503fa4bdcfd5580c75436bc88794b4ae883afa1d92bb0b2a0f5efe"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Rhadamanthys"
		filetype = "executable"

	strings:
		$a1 = "Session\\%u\\MSCTF.Asm.{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide fullword
		$a2 = "MSCTF.Asm.{%08lx-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}" wide fullword
		$a3 = " \"%s\",Options_RunDLL %s" wide fullword
		$a4 = "%%TEMP%%\\vcredist_%05x.dll" wide fullword
		$a5 = "%%APPDATA%%\\vcredist_%05x.dll" wide fullword
		$a6 = "TEQUILABOOMBOOM" wide fullword
		$a7 = "%Systemroot%\\system32\\rundll32.exe" wide fullword

	condition:
		4 of them
}
