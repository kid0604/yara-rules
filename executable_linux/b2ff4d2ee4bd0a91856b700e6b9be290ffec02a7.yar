rule apt_nix_elf_derusbi_kernelModule
{
	meta:
		Author = "@seifreed"
		description = "Detects the presence of the Derusbi kernel module used by APT groups on Linux systems"
		os = "linux"
		filetype = "executable"

	strings:
		$ = "__this_module"
		$ = "init_module"
		$ = "unhide_pid"
		$ = "is_hidden_pid"
		$ = "clear_hidden_pid"
		$ = "hide_pid"
		$ = "license"
		$ = "description"
		$ = "srcversion="
		$ = "depends="
		$ = "vermagic="
		$ = "current_task"
		$ = "sock_release"
		$ = "module_layout"
		$ = "init_uts_ns"
		$ = "init_net"
		$ = "init_task"
		$ = "filp_open"
		$ = "__netlink_kernel_create"
		$ = "kfree_skb"

	condition:
		( uint32(0)==0x4464c457f) and ( all of them )
}
