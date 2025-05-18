rule Windows_Trojan_PlugX_31930182
{
	meta:
		author = "Elastic Security"
		id = "31930182-5bce-4346-aac6-ec5a2b401432"
		fingerprint = "f6a41a717428bb95807116d4dd6745962b83c96609118e067509d130f185365c"
		creation_date = "2025-01-27"
		last_modified = "2025-02-11"
		threat_name = "Windows.Trojan.PlugX"
		reference_sample = "22bbf2f3e262eaeb6d2621396510f6cd81a1ce77600f7f6cb67340335596c544"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan PlugX"
		filetype = "script"

	strings:
		$a1 = "Security WIFI Script" wide fullword
		$a2 = "SS.LOG" wide fullword
		$a3 = "%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X%2.2X" wide fullword
		$a4 = "ping 127.0.0.1 -n 5 > nul 2 > nul" wide fullword
		$a5 = "cmd.exe /c schtasks.exe /create /sc minute /mo 30 /tn \"" wide fullword
		$a6 = "del *.* /f /s /q /a" wide fullword
		$a7 = "ECode: 0x%p," wide fullword
		$a8 = "########" fullword
		$a9 = "Software\\CLASSES\\ms-pu" wide fullword

	condition:
		6 of them
}
