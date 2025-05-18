rule Windows_Generic_MalCert_b8e60712
{
	meta:
		author = "Elastic Security"
		id = "b8e60712-1f7b-4314-a3aa-e841b13d7e92"
		fingerprint = "e9e3236ed9e352213bf24a6b55aa03a9b3f5414fb8ed77d4e19070bbce817c80"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "777325f2c769617cf01e9bfb305b5a47839a1c2c2d1ac067a018ba98781f80e0"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 0C 06 0F DF EF F7 3B 5C E4 69 E4 9A 78 }

	condition:
		all of them
}
