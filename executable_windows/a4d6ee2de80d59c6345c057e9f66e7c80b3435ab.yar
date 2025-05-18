rule Windows_Generic_MalCert_fe1dfef0
{
	meta:
		author = "Elastic Security"
		id = "fe1dfef0-9c56-4e1a-94af-9de1d9d3bce6"
		fingerprint = "ae5565a43abd0c174ac1afb55b7f082dc2b674327b362941374ec2fd099888c1"
		creation_date = "2025-02-05"
		last_modified = "2025-02-10"
		threat_name = "Windows.Generic.MalCert"
		reference_sample = "0c9d7c08f2a74189672a32b4988f19cab6280c82a4c4949fb00370dae8c4b427"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows generic malicious certificate"
		filetype = "executable"

	strings:
		$a1 = { 01 02 02 10 3E A9 D7 D2 B4 B7 4F 29 56 9F 50 6A 64 D5 CC 2A }

	condition:
		all of them
}
