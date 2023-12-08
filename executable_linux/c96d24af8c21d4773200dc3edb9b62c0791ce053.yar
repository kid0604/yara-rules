rule Linux_Exploit_Local_78e50162
{
	meta:
		author = "Elastic Security"
		id = "78e50162-8f1e-4c78-94fe-9b793b006269"
		fingerprint = "a5771dad186d0c23d25efb7b22b11aa0a67148cf6efb9657b09ca6e160c192aa"
		creation_date = "2021-04-06"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Local"
		reference_sample = "706c865257d5e1f5f434ae0f31e11dfc7e16423c4c639cb2763ec0f51bc73300"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux local exploit"
		filetype = "executable"

	strings:
		$a = { 90 90 90 31 C0 31 DB B0 17 CD 80 31 C0 B0 2E CD }

	condition:
		all of them
}
