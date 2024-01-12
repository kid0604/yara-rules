rule M_Hunting_Backdoor_ZIPLINE_1
{
	meta:
		author = "Mandiant"
		description = "This rule detects unique strings in ZIPLINE, a passive ELF backdoor that waits for incoming TCP connections to receive commands from the threat actor."
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		date = "2024-01-11"
		score = 75
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "SSH-2.0-OpenSSH_0.3xx" ascii
		$s2 = "$(exec $installer $@)" ascii
		$t1 = "./installer/do-install" ascii
		$t2 = "./installer/bom_files/" ascii
		$t3 = "/tmp/data/root/etc/ld.so.preload" ascii
		$t4 = "/tmp/data/root/home/etc/manifest/exclusion_list" ascii

	condition:
		uint32(0)==0x464c457f and filesize <5MB and ((1 of ($s*)) or (3 of ($t*)))
}
