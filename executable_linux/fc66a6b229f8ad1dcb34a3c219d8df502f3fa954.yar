rule Linux_Exploit_CVE_2021_3156_7f5672d0
{
	meta:
		author = "Elastic Security"
		id = "7f5672d0-73f1-4143-b3e2-3aed110779e3"
		fingerprint = "71e90dd36342686bb4be7ef86e1ceb2e915c70f437f4733ddcc5175860ca4084"
		creation_date = "2021-09-15"
		last_modified = "2021-09-21"
		threat_name = "Linux.Exploit.CVE-2021-3156"
		reference_sample = "1a4517d2582ac97b88ae568c23e75beba93daf8518bd3971985d6a798049fd61"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2021-3156"
		filetype = "executable"

	strings:
		$a1 = "/tmp/gogogo123456789012345678901234567890go" fullword
		$a2 = "gg:$5$a$gemgwVPxLx/tdtByhncd4joKlMRYQ3IVwdoBXPACCL2:0:0:gg:/root:/bin/bash" fullword
		$sudo = "sudoedit" fullword
		$msg1 = "succes with sleep time %d us" fullword
		$msg2 = "[+] Success with %d attempts" fullword
		$msg3 = "symlink 2nd time success at: %d" fullword

	condition:
		( any of ($a*)) or ($sudo and 2 of ($msg*))
}
