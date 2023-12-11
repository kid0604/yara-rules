rule Linux_Exploit_Wuftpd_0991e62f
{
	meta:
		author = "Elastic Security"
		id = "0991e62f-af72-416a-b88b-6bc8a501b8bb"
		fingerprint = "642c7b059fa604a0a5110372e2247da9625b07008b012fd498670a6dd1b29974"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Wuftpd"
		reference_sample = "c0b6303300f38013840abe17abe192db6a99ace78c83bc7ef705f5c568bc98fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Linux exploit for WU-FTPD"
		filetype = "executable"

	strings:
		$a = { F3 8D 4E 08 8D 56 0C B0 0B CD 80 31 C0 31 DB }

	condition:
		all of them
}
