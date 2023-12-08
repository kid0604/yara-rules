rule Windows_Trojan_PowerSeal_2e50f393
{
	meta:
		author = "Elastic Security"
		id = "2e50f393-40c0-49f7-882e-33f914eff32d"
		fingerprint = "9b7beb5af64bc57d78cfb8f5bf8134461d8f2fbe7c935a0fa2b44fb51160a28d"
		creation_date = "2023-05-10"
		last_modified = "2023-06-13"
		threat_name = "Windows.Trojan.PowerSeal"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects the presence of Windows Trojan PowerSeal"
		filetype = "executable"

	strings:
		$a1 = "[+] Loading PowerSeal"
		$a2 = "[!] Failed to exec PowerSeal"
		$a3 = "AppDomain: unable to get the name!"

	condition:
		2 of them
}
