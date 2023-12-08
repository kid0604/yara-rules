rule FE_Trojan_SH_ATRIUM_1
{
	meta:
		author = "Mandiant"
		date = "2021-04-16"
		hash = "a631b7a8a11e6df3fccb21f4d34dbd8a"
		description = "Detects samples mentioned in PulseSecure report"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "CGI::param("
		$s2 = "Cache-Control: no-cache"
		$s3 = "system("
		$s4 = /sed -i [^\r\n]{1,128}CGI::param\([^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Cache-Control: no-cache[^\r\n]{1,128}print[\x20\x09]{1,32}[^\r\n]{1,128}Content-type: text\/html[^\r\n]{1,128}my [^\r\n]{1,128}=[\x09\x20]{0,32}CGI::param\([^\r\n]{1,128}system\(/

	condition:
		all of them
}
