rule Linux_Shellcode_Generic_99b991cd
{
	meta:
		author = "Elastic Security"
		id = "99b991cd-a5ca-475c-8c10-e43b9d22d26e"
		fingerprint = "ed904a3214ccf43482e3ddf75f3683fea45f7c43a2f1860bac427d7d15d8c399"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Shellcode.Generic"
		reference_sample = "954b5a073ce99075b60beec72936975e48787bea936b4c5f13e254496a20d81d"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects generic Linux shellcode"
		filetype = "executable"

	strings:
		$a = { 6E 89 E3 50 53 89 E1 B0 0B CD 80 00 4C 65 6E 67 }

	condition:
		all of them
}
