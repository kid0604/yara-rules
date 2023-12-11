rule FE_APT_Trojan_PL_RADIALPULSE_1
{
	meta:
		author = "Mandiant"
		date = "2021-04-16"
		sha256 = "d72daafedf41d484f7f9816f7f076a9249a6808f1899649b7daa22c0447bb37b"
		description = "Detects samples mentioned in PulseSecure report"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "->getRealmInfo()->{name}"
		$s2 = /open\(\*fd,[\x09\x20]{0,32}[\x22\x27]>>/
		$s3 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]realm=\$/
		$s4 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]username=\$/
		$s5 = /syswrite\(\*fd,[\x09\x20]{0,32}[\x22\x27]password=\$/

	condition:
		(@s1[1]<@s2[1]) and (@s2[1]<@s3[1]) and $s4 and $s5
}
