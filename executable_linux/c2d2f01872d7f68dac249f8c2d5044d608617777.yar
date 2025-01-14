rule Linux_Rootkit_Diamorphine_66eb93c7
{
	meta:
		author = "Elastic Security"
		id = "66eb93c7-3f26-43ce-b43e-550c6fd44927"
		fingerprint = "e045a6f3359443a11fa609eefedb0aa92f035e91e087e3472461c10bb28f0cc1"
		creation_date = "2024-11-13"
		last_modified = "2024-11-22"
		threat_name = "Linux.Rootkit.Diamorphine"
		reference_sample = "01fb490fbe2c2b5368cc227abd97e011e83b5e99bb80945ef599fc80e85f8545"
		severity = 100
		arch_context = "x86, arm64"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "linux"
		description = "Detects the presence of Linux Rootkit Diamorphine"
		filetype = "executable"

	strings:
		$rk1 = "sys_call_table"
		$rk2 = "kallsyms_lookup_name"
		$rk3 = "retpoline=Y"
		$func1 = "get_syscall_table_bf"
		$func2 = "is_invisible"
		$func3 = "hacked_getdents64"
		$func4 = "orig_getdents64"
		$func5 = "give_root"
		$func6 = "module_show"
		$func7 = "module_hide"
		$func8 = "hacked_kill"
		$func9 = "write_cr0_forced"

	condition:
		1 of ($rk*) and 3 of ($func*)
}
