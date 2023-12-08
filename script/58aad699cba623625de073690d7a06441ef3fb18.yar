rule network_irc
{
	meta:
		author = "x0r"
		description = "Communications over IRC network"
		version = "0.1"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "NICK"
		$s2 = "PING"
		$s3 = "JOIN"
		$s4 = "USER"
		$s5 = "PRIVMSG"

	condition:
		all of them
}
