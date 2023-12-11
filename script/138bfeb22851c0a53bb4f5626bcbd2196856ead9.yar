rule FE_APT_Webshell_PL_STEADYPULSE_1
{
	meta:
		author = "Mandiant"
		date = "2021-04-16"
		sha256 = "168976797d5af7071df257e91fcc31ce1d6e59c72ca9e2f50c8b5b3177ad83cc"
		description = "Detects samples mentioned in PulseSecure report"
		reference = "https://www.fireeye.com/blog/threat-research/2021/04/suspected-apt-actors-leverage-bypass-techniques-pulse-secure-zero-day.html"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "parse_parameters"
		$s2 = "s/\\+/ /g"
		$s3 = "s/%(..)/pack("
		$s4 = "MIME::Base64::encode($"
		$s5 = "$|=1;"
		$s6 = "RC4("
		$s7 = "$FORM{'cmd'}"

	condition:
		all of them
}
