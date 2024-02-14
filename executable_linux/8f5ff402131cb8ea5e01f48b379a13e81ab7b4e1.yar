rule Linux_Ransomware_Lockbit_d248e80e
{
	meta:
		author = "Elastic Security"
		id = "d248e80e-3e2f-4957-adc3-0c912b0cd386"
		fingerprint = "417ecf5a0b6030ed5b973186efa1e72dfa56886ba6cfc5fbf615e0814c24992f"
		creation_date = "2023-07-27"
		last_modified = "2024-02-13"
		threat_name = "Linux.Ransomware.Lockbit"
		reference_sample = "4800a67ceff340d2ab4f79406a01f58e5a97d589b29b35394b2a82a299b19745"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Ransomware.Lockbit ransomware activity"
		filetype = "executable"

	strings:
		$a1 = "restore-my-files.txt" fullword
		$b1 = "xkeyboard-config" fullword
		$b2 = "bootsect.bak" fullword
		$b3 = "lockbit" fullword
		$b4 = "Error: %s" fullword
		$b5 = "crypto_generichash_blake2b_final" fullword

	condition:
		$a1 and 2 of ($b*)
}
