rule WildNeutron_Sample_7
{
	meta:
		description = "Wild Neutron APT Sample Rule - file a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "a14d31eb965ea8a37ebcc3b5635099f2ca08365646437c770212d534d504ff3c"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "checking match for '%s' user %s host %s addr %s" fullword ascii
		$s1 = "PEM_read_bio_PrivateKey failed" fullword ascii
		$s2 = "usage: %s [-ehR] [-f log_facility] [-l log_level] [-u umask]" fullword ascii
		$s3 = "%s %s for %s%.100s from %.200s port %d%s" fullword ascii
		$s4 = "clapi32.dll" fullword ascii
		$s5 = "Connection from %s port %d" fullword ascii
		$s6 = "/usr/etc/ssh_known_hosts" fullword ascii
		$s7 = "Version: %s - %s %s %s %s" fullword ascii
		$s8 = "[-] connect()" fullword ascii
		$s9 = "/bin/sh /usr/etc/sshrc" fullword ascii
		$s10 = "kexecdhs.c" fullword ascii
		$s11 = "%s: setrlimit(RLIMIT_FSIZE, { 0, 0 }): %s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and all of them
}
