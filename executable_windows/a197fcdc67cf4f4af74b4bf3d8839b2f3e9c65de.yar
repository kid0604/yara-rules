rule Windows_Trojan_BlackShades_9d095c44
{
	meta:
		author = "Elastic Security"
		id = "9d095c44-5047-453e-8435-f30de94565e6"
		fingerprint = "be7d4c8200c293c3c8046d9f87b0d127ff051679ae1caeab12c533ea4309a1fc"
		creation_date = "2022-02-28"
		last_modified = "2022-04-12"
		threat_name = "Windows.Trojan.BlackShades"
		reference_sample = "e58e352edaa8ae7f95ab840c53fcaf7f14eb640df9223475304788533713c722"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan BlackShades variant 9d095c44"
		filetype = "executable"

	strings:
		$a1 = "*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
		$a2 = "@*\\AD:\\Blackshades Project\\bs_net\\server\\server.vbp" wide fullword
		$a3 = "D:\\Blackshades Project\\bs_net\\loginserver\\msvbvm60.dll\\3" ascii fullword
		$b1 = "modSniff" ascii fullword
		$b2 = "UDPFlood" ascii fullword
		$b3 = "\\nir_cmd.bss speak text " wide fullword
		$b4 = "\\pws_chro.bss" wide fullword
		$b5 = "tmrLiveLogger" ascii fullword

	condition:
		1 of ($a*) or all of ($b*)
}
