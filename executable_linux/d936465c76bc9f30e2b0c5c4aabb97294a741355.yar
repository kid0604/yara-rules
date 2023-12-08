rule apt_nix_elf_derusbi_kernelModule_alt_1
{
	meta:
		description = "Detects Derusbi Backdoor ELF Kernel Module"
		author = "Fidelis Cybersecurity"
		date = "2016/02/29"
		modified = "2023-05-04"
		reference = "https://github.com/fideliscyber/indicators/tree/master/FTA-1021"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "__this_module"
		$s2 = "init_module"
		$s3 = "unhide_pid"
		$s4 = "is_hidden_pid"
		$s5 = "clear_hidden_pid"
		$s6 = "hide_pid"
		$s7 = "license"
		$s8 = "description"
		$s9 = "srcversion="
		$s10 = "depends="
		$s12 = "vermagic="
		$s13 = "current_task"
		$s14 = "sock_release"
		$s15 = "module_layout"
		$s16 = "init_uts_ns"
		$s17 = "init_net"
		$s18 = "init_task"
		$s19 = "filp_open"
		$s20 = "__netlink_kernel_create"
		$s21 = "kfree_skb"

	condition:
		uint32(0)==0x464c457f and all of them
}
