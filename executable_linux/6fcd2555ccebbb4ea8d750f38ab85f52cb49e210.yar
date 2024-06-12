rule Linux_Generic_Threat_a40aaa96
{
	meta:
		author = "Elastic Security"
		id = "a40aaa96-4dcf-45b8-a95e-7ed7f27a31b6"
		fingerprint = "ce2da00db88bba513f910bdb00e1c935d1d972fe20558e2ec8e3c57cdbd5b7be"
		creation_date = "2024-05-21"
		last_modified = "2024-06-12"
		threat_name = "Linux.Generic.Threat"
		reference_sample = "6f965252141084524f85d94169b13938721bce24cc986bf870473566b7cfd81b"
		severity = 50
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux generic threat"
		filetype = "executable"

	strings:
		$a1 = { 6D 61 69 6E 2E 55 69 6E 74 33 32 6E }
		$a2 = { 6D 61 69 6E 2E 47 65 74 72 61 6E 64 }
		$a3 = { 6D 61 69 6E 2E 28 2A 52 4E 47 29 2E 55 69 6E 74 33 32 }

	condition:
		all of them
}
