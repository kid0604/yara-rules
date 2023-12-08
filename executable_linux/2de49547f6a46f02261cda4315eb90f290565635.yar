rule Linux_Exploit_Ramen_01b205eb
{
	meta:
		author = "Elastic Security"
		id = "01b205eb-4718-4ffd-9fdc-b9de567c4603"
		fingerprint = "a39afcf7cec82dc511fd39b4a019ef161250afe7cb0880e488badb56d021cc9f"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Ramen"
		reference_sample = "c0b6303300f38013840abe17abe192db6a99ace78c83bc7ef705f5c568bc98fd"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux.Exploit.Ramen"
		filetype = "executable"

	strings:
		$a = { 00 31 C0 31 DB 31 C9 B0 46 CD 80 31 C0 31 DB 43 }

	condition:
		all of them
}
