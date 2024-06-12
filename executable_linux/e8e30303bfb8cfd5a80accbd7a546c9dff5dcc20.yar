rule Linux_Exploit_IOUring_d04c1c19
{
	meta:
		author = "Elastic Security"
		id = "d04c1c19-9303-41cd-ae9c-149bb137e6cc"
		fingerprint = "0e50d858b8e5428a964dc70b0132659defd61e8965331fa327b1f454bf922162"
		creation_date = "2024-04-07"
		last_modified = "2024-06-12"
		threat_name = "Linux.Exploit.IOUring"
		reference_sample = "29e6a5f7b36e271219601528f3fd70831aacb8b9f05722779faa40afc97b3b60"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit using IOUring"
		filetype = "executable"

	strings:
		$s1 = "io_uring_"
		$s2 = "kaslr_leak: 0x%llx"
		$s3 = "kaslr_base: 0x%llx"

	condition:
		all of them
}