rule FE_APT_Trojan_Linux_PACEMAKER
{
	meta:
		author = "Mandiant"
		date = "2021-04-16"
		hash = "d7881c4de4d57828f7e1cab15687274b"
		description = "Detects samples mentioned in PulseSecure report"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		os = "linux"
		filetype = "executable"

	strings:
		$s1 = "\x00Name:%s || Pwd:%s || AuthNum:%s\x0a\x00"
		$s2 = "\x00/proc/%d/mem\x00"
		$s3 = "\x00/proc/%s/maps\x00"
		$s4 = "\x00/proc/%s/cmdline\x00"

	condition:
		( uint32(0)==0x464c457f) and all of them
}
