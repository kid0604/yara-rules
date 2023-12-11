rule FE_APT_Trojan_PL_RADIALPULSE_2
{
	meta:
		author = "Mandiant"
		date = "2021-04-16"
		hash = "4a2a7cbc1c8855199a27a7a7b51d0117"
		description = "Detects samples mentioned in PulseSecure report"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "open(*fd,"
		$s2 = "syswrite(*fd,"
		$s3 = "close(*fd);"
		$s4 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>\/tmp\/[\w.]{1,128}[\x22\x27]\);[\x09\x20]{0,32}syswrite\(\*fd,[\x09\x20]{0,32}/
		$s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27][\w]{1,128}=\$\w{1,128} ?[\x22\x27],[\x09\x20]{0,32}5000\)/

	condition:
		all of them
}
