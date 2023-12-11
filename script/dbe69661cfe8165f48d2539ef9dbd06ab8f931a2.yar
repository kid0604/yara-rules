rule ld_preload_backdoor
{
	meta:
		description = "Detects the presence of ld_preload backdoor"
		os = "linux"
		filetype = "script"

	strings:
		$ = "killall -9 \".basename(\"/usr/bin/host"

	condition:
		any of them
}
