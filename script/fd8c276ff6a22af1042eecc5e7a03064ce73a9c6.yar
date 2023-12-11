rule Windows_Trojan_SysJoker_1ef19a12
{
	meta:
		author = "Elastic Security"
		id = "1ef19a12-ee26-47da-8d65-272f6749b476"
		fingerprint = "9123af8b8b27ebfb9199e70eb34d43378b1796319186d5d848d650a8be02d5d5"
		creation_date = "2022-02-17"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.SysJoker"
		reference_sample = "61df74731fbe1eafb2eb987f20e5226962eeceef010164e41ea6c4494a4010fc"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SysJoker variant"
		filetype = "script"

	strings:
		$a1 = "';Write-Output \"Time taken : $((Get - Date).Subtract($start_time).Seconds) second(s)\"" ascii fullword
		$a2 = "powershell.exe Expand-Archive -LiteralPath '" ascii fullword
		$a3 = "powershell.exe Invoke-WebRequest -Uri '" ascii fullword
		$a4 = "\\recoveryWindows.zip" ascii fullword

	condition:
		3 of them
}
