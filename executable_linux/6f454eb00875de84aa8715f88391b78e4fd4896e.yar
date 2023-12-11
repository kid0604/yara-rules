rule Linux_Exploit_CVE_2022_0847_e831c285
{
	meta:
		author = "Elastic Security"
		id = "e831c285-b2b9-49f3-a87c-3deb806e31e4"
		fingerprint = "376b791f9bb5f48d0f41ead4e48b5bcc74cb68002bb7c170760428ace169457e"
		creation_date = "2022-03-10"
		last_modified = "2022-03-14"
		threat_name = "Linux.Exploit.CVE-2022-0847"
		reference_sample = "c6b2cef2f2bc04e3ae33e0d368eb39eb5ea38d1bca390df47f7096117c1aecca"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2022-0847"
		filetype = "executable"

	strings:
		$pp = "prepare_pipe"
		$s1 = "splice failed"
		$s2 = "short splice"
		$s3 = "short write"
		$s4 = "hijacking suid binary"
		$s5 = "Usage: %s TARGETFILE OFFSET DATA"
		$s6 = "Usage: %s SUID"
		$bs1 = { B8 00 10 00 00 81 7D EC 00 10 00 00 0F 46 45 EC 89 45 FC 8B 55 FC 48 8B 45 D8 48 83 C0 04 8B 00 48 8D 35 }
		$bs2 = { B8 00 10 00 00 81 7D F0 00 10 00 00 0F 46 45 F0 89 45 F8 8B 55 F8 48 8B 45 D8 8B 00 48 }

	condition:
		($pp and 2 of ($s*)) or ( all of ($bs*))
}
