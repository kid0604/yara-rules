rule Linux_Exploit_CVE_2021_3490_d369d615
{
	meta:
		author = "Elastic Security"
		id = "d369d615-d2a3-4f9d-b5c7-eb0fac5d43e7"
		fingerprint = "4f8f4c7fabe32a023f8aafb817e2c27c5a5e0e9246ddccacf99a47f2ab850014"
		creation_date = "2021-11-12"
		last_modified = "2022-01-26"
		threat_name = "Linux.Exploit.CVE-2021-3490"
		reference_sample = "e65ba616942fd1e893e10898d546fe54458debbc42e0d6826aff7a4bb4b2cf19"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects Linux exploit CVE-2021-3490"
		filetype = "executable"

	strings:
		$c1 = "frame_dummy_init_array_entry"
		$c2 = "leak_oob_map_ptr"
		$c3 = "overwrite_cred"
		$c4 = "obj_get_info_by_fd"
		$c5 = "kernel_write_uint"
		$c6 = "search_init_pid_ns_kstrtab"
		$c7 = "search_init_pid_ns_ksymtab"
		$msg1 = "failed to leak ptr to BPF map"
		$msg2 = "preparing to overwrite creds..."
		$msg3 = "success! enjoy r00t"
		$msg4 = "Useage: %s <path to program to execute as root>"
		$msg5 = "searching for init_pid_ns in ksymtab"

	condition:
		4 of them
}
