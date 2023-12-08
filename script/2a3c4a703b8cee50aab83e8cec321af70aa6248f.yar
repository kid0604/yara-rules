rule LinuxHacktool_eyes_pscan2_2
{
	meta:
		description = "Linux hack tools - file pscan2.c"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "eb024dfb441471af7520215807c34d105efa5fd8"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "snprintf(outfile, sizeof(outfile) - 1, \"scan.log\", argv[1], argv[2]);" fullword ascii
		$s2 = "printf(\"Usage: %s <b-block> <port> [c-block]\\n\", argv[0]);" fullword ascii
		$s3 = "printf(\"\\n# pscan completed in %u seconds. (found %d ips)\\n\", (time(0) - sca" ascii
		$s19 = "connlist[i].addr.sin_family = AF_INET;" fullword ascii
		$s20 = "snprintf(last, sizeof(last) - 1, \"%s.%d.* (total: %d) (%.1f%% done)\"," fullword ascii

	condition:
		2 of them
}
