rule Linux_Shellcode_Generic_24b9aa12
{
	meta:
		author = "Elastic Security"
		id = "24b9aa12-92b2-492d-9a0e-078cdab5830a"
		fingerprint = "0ded0ad2fdfff464bf9a0b5a59b8edfe1151a513203386daae6f9f166fd48e5c"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "24b2c1ccbbbe135d40597fbd23f7951d93260d0039e0281919de60fa74eb5977"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "executable"

	strings:
		$a = { 6E 89 E3 89 C1 89 C2 B0 0B CD 80 31 C0 40 CD 80 }

	condition:
		all of them
}
