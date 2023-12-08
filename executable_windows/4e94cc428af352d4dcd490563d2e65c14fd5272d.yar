rule Windows_Trojan_CobaltStrike_c851687a
{
	meta:
		author = "Elastic Security"
		id = "c851687a-aac6-43e7-a0b6-6aed36dcf12e"
		fingerprint = "70224e28a223d09f2211048936beb9e2d31c0312c97a80e22c85e445f1937c10"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies UAC Bypass module from Cobalt Strike"
		threat_name = "Windows.Trojan.CobaltStrike"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "bypassuac.dll" ascii fullword
		$a2 = "bypassuac.x64.dll" ascii fullword
		$a3 = "\\\\.\\pipe\\bypassuac" ascii fullword
		$b1 = "\\System32\\sysprep\\sysprep.exe" wide fullword
		$b2 = "[-] Could not write temp DLL to '%S'" ascii fullword
		$b3 = "[*] Cleanup successful" ascii fullword
		$b4 = "\\System32\\cliconfg.exe" wide fullword
		$b5 = "\\System32\\eventvwr.exe" wide fullword
		$b6 = "[-] %S ran too long. Could not terminate the process." ascii fullword
		$b7 = "[*] Wrote hijack DLL to '%S'" ascii fullword
		$b8 = "\\System32\\sysprep\\" wide fullword
		$b9 = "[-] COM initialization failed." ascii fullword
		$b10 = "[-] Privileged file copy failed: %S" ascii fullword
		$b11 = "[-] Failed to start %S: %d" ascii fullword
		$b12 = "ReflectiveLoader"
		$b13 = "[-] '%S' exists in DLL hijack location." ascii fullword
		$b14 = "[-] Cleanup failed. Remove: %S" ascii fullword
		$b15 = "[+] %S ran and exited." ascii fullword
		$b16 = "[+] Privileged file copy success! %S" ascii fullword

	condition:
		2 of ($a*) or 10 of ($b*)
}
