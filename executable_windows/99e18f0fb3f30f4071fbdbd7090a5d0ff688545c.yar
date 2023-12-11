rule Windows_Ransomware_WhisperGate_3476008e
{
	meta:
		author = "Elastic Security"
		id = "3476008e-1c98-4606-b60b-7fef0e360711"
		fingerprint = "0b8caff8cf9342bd50053712bf4c9aeab68532e340cc5e6cf400105afc150e39"
		creation_date = "2022-01-18"
		last_modified = "2022-01-18"
		threat_name = "Windows.Ransomware.WhisperGate"
		reference_sample = "9ef7dbd3da51332a78eff19146d21c82957821e464e8133e9594a07d716d892d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware WhisperGate"
		filetype = "executable"

	strings:
		$a1 = "cmd.exe /min /C ping 111.111.111.111 -n 5 -w 10 > Nul & Del /f /q \"%s\"" ascii fullword
		$a2 = "%.*s.%x" wide fullword
		$a3 = "A:\\Windows" wide fullword
		$a4 = ".ONETOC2" wide fullword

	condition:
		all of them
}
