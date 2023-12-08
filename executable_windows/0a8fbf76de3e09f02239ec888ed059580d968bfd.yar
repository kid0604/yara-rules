rule Windows_Trojan_Bumblebee_70bed4f3
{
	meta:
		author = "Elastic Security"
		id = "70bed4f3-f515-4186-ac6c-e9db72b8a95a"
		fingerprint = "016477598ce022cc75f591d1c72535a3353ecc4e888642e72aa29476464a8c2f"
		creation_date = "2022-04-28"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.Bumblebee"
		reference_sample = "9fff05a5aa9cbbf7d37bc302d8411cbd63fb3a28dc6f5163798ae899b9edcda6"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan Bumblebee"
		filetype = "executable"

	strings:
		$a1 = "Checking Virtual PC processes %s " wide fullword
		$a2 = "SELECT * FROM Win32_ComputerSystemProduct" ascii fullword
		$a3 = "Injection-Date" ascii fullword
		$a4 = " -Command \"Wait-Process -Id " ascii fullword
		$a5 = "%WINDIR%\\System32\\wscript.exe" wide fullword
		$a6 = "objShell.Run \"rundll32.exe my_application_path"
		$a7 = "Checking reg key HARDWARE\\Description\\System - %s is set to %s" wide fullword

	condition:
		5 of them
}
