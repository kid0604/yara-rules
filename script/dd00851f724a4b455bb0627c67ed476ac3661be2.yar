rule Linux_Exploit_Perl_982bb709
{
	meta:
		author = "Elastic Security"
		id = "982bb709-beec-4f7f-b249-44b1fb46c3be"
		fingerprint = "a2f68acb31b84e93f902aeb838ad550e1644c20e1c8060bb8de8ad57fa4ba4bb"
		creation_date = "2021-01-12"
		last_modified = "2021-09-16"
		threat_name = "Linux.Exploit.Perl"
		reference_sample = "f3e4e2b5af9d0c72aae83cec57e5c091a95c549f826e8f13559aaf7d300f6e13"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit written in Perl"
		filetype = "script"

	strings:
		$a = { 54 75 65 20 53 65 70 20 32 31 20 31 36 3A 34 38 3A 31 32 20 }

	condition:
		all of them
}
