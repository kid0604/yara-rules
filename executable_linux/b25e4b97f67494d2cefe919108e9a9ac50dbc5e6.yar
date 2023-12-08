rule APT_MAL_WinntiLinux_Dropper_AzazelFork_May19 : azazel_fork
{
	meta:
		description = "Detection of Linux variant of Winnti"
		author = "Silas Cutler (havex [@] chronicle.security), Chronicle Security"
		version = "1.0"
		date = "2019-05-15"
		TLP = "White"
		sha256 = "4741c2884d1ca3a40dadd3f3f61cb95a59b11f99a0f980dbadc663b85eb77a2a"
		os = "linux"
		filetype = "executable"

	strings:
		$config_decr = { 48 89 45 F0 C7 45 EC 08 01 00 00 C7 45 FC 28 00 00 00 EB 31 8B 45 FC 48 63 D0 48 8B 45 F0 48 01 C2 8B 45 FC 48 63 C8 48 8B 45 F0 48 01 C8 0F B6 00 89 C1 8B 45 F8 89 C6 8B 45 FC 01 F0 31 C8 88 02 83 45 FC 01 }
		$export1 = "our_sockets"
		$export2 = "get_our_pids"

	condition:
		uint16(0)==0x457f and all of them
}
