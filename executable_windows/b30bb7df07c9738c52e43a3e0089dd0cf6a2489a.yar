rule Windows_Exploit_RpcJunction_0405253b
{
	meta:
		author = "Elastic Security"
		id = "0405253b-d91f-420e-b2e5-7f4aebeb7709"
		fingerprint = "bd5f1c040f6fcf16e507d2c3cb94013ea17d85b2428b85ba1d84005cc44739ec"
		creation_date = "2024-02-28"
		last_modified = "2024-03-21"
		threat_name = "Windows.Exploit.RpcJunction"
		reference_sample = "05588fe3d2aae1273e9d0b0ac00c867d92bcdea41c33661760dcbe84439e7949"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows exploit RpcJunction"
		filetype = "executable"

	strings:
		$s1 = "NtSetInformationFile"
		$s2 = "DefineDosDevice"
		$s3 = "\\GLOBALROOT\\RPC Control\\" wide nocase

	condition:
		all of them
}
