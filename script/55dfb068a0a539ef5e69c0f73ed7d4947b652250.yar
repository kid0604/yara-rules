rule Linux_Exploit_CVE_2021_4034_1c8f235d
{
	meta:
		author = "Elastic Security"
		id = "1c8f235d-1345-4d5f-a5db-427dbbe6fc9a"
		fingerprint = "b145df35499a55e3e920f7701aab3b2f19af9fafbb2e0c1af53cb0b318ad06a6"
		creation_date = "2022-01-26"
		last_modified = "2022-07-22"
		threat_name = "Linux.Exploit.CVE-2021-4034"
		reference_sample = "94052c42aa41d0911e4b425dcfd6b829cec8f673bf1245af4050ef9c257f6c4b"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2021-4034"
		filetype = "script"

	strings:
		$s1 = "PATH=GCONV_PATH="
		$s2 = "pkexec"

	condition:
		all of them
}
