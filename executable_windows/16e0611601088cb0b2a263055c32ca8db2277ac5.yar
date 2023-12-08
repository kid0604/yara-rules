rule Windows_Trojan_SiestaGraph_d801ce71
{
	meta:
		author = "Elastic Security"
		id = "d801ce71-2e3d-47bb-a194-c68b437d8ecc"
		fingerprint = "8e1d95313526650c2fa3dd00e779aec0e62d1a2273722ad913100eab003fc8b6"
		creation_date = "2023-09-12"
		last_modified = "2023-09-20"
		threat_name = "Windows.Trojan.SiestaGraph"
		reference_sample = "fe8f99445ad139160a47b109a8f3291eef9c6a23b4869c48d341380d608ed4cb"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Trojan SiestaGraph"
		filetype = "executable"

	strings:
		$hashgenfunc = { 02 2C ?? 20 [4] 0A 16 0B 2B ?? 02 07 6F [4] 06 61 20 [4] 5A 0A 07 17 58 0B 07 02 6F [4] 32 ?? }
		$sendpostfunc = { 72 [4] 72 [4] 72 [4] 02 73 [4] 73 [4] 28 [4] 0A 72 [4] 72 [4] 06 28 [4] 2A }
		$command15 = { 25 16 1F 3A 9D 6F [4] 17 9A 13 ?? 11 ?? 28 [4] 13 ?? 11 ?? 28 [4] 11 ?? 28 [4] 2C 33 28 [4] 28 [4] 6F [4] 6F [4] 11 ?? 28 [4] 09 7B [4] 18 9A 72 [4] 72 [4] 28 [4] 26 DE }

	condition:
		all of them
}
