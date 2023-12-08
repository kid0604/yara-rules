rule shellbot_pl
{
	meta:
		description = "Semi-Auto-generated  - file shellbot.pl.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		hash = "b2a883bc3c03a35cfd020dd2ace4bab8"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s0 = "ShellBOT"
		$s1 = "PacktsGr0up"
		$s2 = "CoRpOrAtIoN"
		$s3 = "# Servidor de irc que vai ser usado "
		$s4 = "/^ctcpflood\\s+(\\d+)\\s+(\\S+)"

	condition:
		2 of them
}
