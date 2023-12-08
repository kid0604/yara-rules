rule MAL_Xbash_SH_Sep18
{
	meta:
		description = "Detects Xbash malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://researchcenter.paloaltonetworks.com/2018/09/unit42-xbash-combines-botnet-ransomware-coinmining-worm-targets-linux-windows/"
		date = "2018-09-18"
		modified = "2023-01-06"
		hash1 = "a27acc07844bb751ac33f5df569fd949d8b61dba26eb5447482d90243fc739af"
		hash2 = "de63ce4a42f06a5903b9daa62b67fcfbdeca05beb574f966370a6ae7fd21190d"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "echo \"*/5 * * * * curl -fsSL" fullword ascii
		$s2 = ".sh|sh\" > /var/spool/cron/root" ascii
		$s3 = "#chmod +x /tmp/hawk" fullword ascii
		$s4 = "if [ ! -f \"/tmp/root.sh\" ]" fullword ascii
		$s5 = ".sh > /tmp/lower.sh" ascii
		$s6 = "chmod 777 /tmp/root.sh" fullword ascii
		$s7 = "-P /tmp && chmod +x /tmp/pools.txt" fullword ascii
		$s8 = "-C /tmp/pools.txt>/dev/null 2>&1" ascii

	condition:
		uint16(0)==0x2123 and filesize <3KB and 1 of them
}
