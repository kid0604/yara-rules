rule Windows_Trojan_Bughatch_98f3c0be
{
	meta:
		author = "Elastic Security"
		id = "98f3c0be-1327-4ba2-9320-c1a9ce90b4a4"
		fingerprint = "1ac6b1285e1925349e4e578de0b2f1cf8a008cddbb1a20eb8768b1fcc4b0c8d3"
		creation_date = "2022-05-09"
		last_modified = "2022-06-09"
		threat_name = "Windows.Trojan.Bughatch"
		reference_sample = "b495456a2239f3ba48e43ef295d6c00066473d6a7991051e1705a48746e8051f"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan Bughatch"
		filetype = "script"

	strings:
		$a1 = "-windowstyle hidden -executionpolicy bypass -file"
		$a2 = "C:\\Windows\\SysWOW64\\WindowsPowerShell\\v1.0\\powershell.exe"
		$a3 = "ReflectiveLoader"
		$a4 = "\\Sysnative\\"
		$a5 = "TEMP%u.CMD"
		$a6 = "TEMP%u.PS1"
		$a7 = "\\TEMP%d.%s"
		$a8 = "NtSetContextThread"
		$a9 = "NtResumeThread"

	condition:
		6 of them
}
