rule Windows_Trojan_BruteRatel_1916686d
{
	meta:
		author = "Elastic Security"
		id = "1916686d-4821-4e5a-8290-58336d01997f"
		fingerprint = "86304082d3eda2f160465f0af0a3feae1aa9695727520e51f139d951e50d6efc"
		creation_date = "2022-06-23"
		last_modified = "2022-12-01"
		threat_name = "Windows.Trojan.BruteRatel"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Yara rule for detecting Windows Trojan BruteRatel"
		filetype = "executable"

	strings:
		$a1 = "[+] Spoofed PPID => %lu" wide fullword
		$a2 = "[-] Child process not set" wide fullword
		$a3 = "[+] Crisis Monitor: Already Running" wide fullword
		$a4 = "[+] Screenshot downloaded: %S" wide fullword
		$a5 = "s[-] Duplicate listener: %S" wide fullword
		$a6 = "%02d%02d%d_%02d%02d%2d%02d.png" wide fullword
		$a7 = "[+] Added Socks Profile" wide fullword
		$a8 = "[+] Dump Size: %d Mb" wide fullword
		$a9 = "[+] Enumerating PID: %lu [%ls]" wide fullword
		$a10 = "[+] Dump Size: %d Mb" wide fullword
		$a11 = "[+] SAM key: " wide fullword
		$a12 = "[+] Token removed: '%ls'" wide fullword
		$a13 = "[Tasks] %02d => 0x%02X 0x%02X" wide fullword
		$b1 = { 48 83 EC ?? 48 8D 35 ?? ?? ?? ?? 4C 63 E2 31 D2 48 8D 7C 24 ?? 48 89 CB 4D 89 E0 4C 89 E5 E8 ?? ?? ?? ?? B9 ?? ?? ?? ?? F3 A4 31 F6 BF ?? ?? ?? ?? 39 F5 7E ?? E8 ?? ?? ?? ?? 99 F7 FF 48 63 D2 8A 44 14 ?? 88 04 33 48 FF C6 EB ?? }

	condition:
		4 of ($a*) or 1 of ($b*)
}
