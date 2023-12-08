rule Windows_Trojan_Metasploit_f7f826b4
{
	meta:
		author = "Elastic Security"
		id = "f7f826b4-6456-4819-bc0c-993aeeb7e325"
		fingerprint = "9b07dc54d5015d0f0d84064c5a989f94238609c8167cae7caca8665930a20f81"
		creation_date = "2021-03-23"
		last_modified = "2021-08-23"
		description = "Identifies metasploit kernel->user shellcode. Likely used in ETERNALBLUE and BlueKeep exploits."
		threat_name = "Windows.Trojan.Metasploit"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = { 48 92 31 C9 51 51 49 89 C9 4C 8D 05 0? 00 00 00 89 CA 48 83 EC 20 FF D0 48 83 C4 30 C3 }

	condition:
		$a1
}
