import "pe"

rule LinuxTsunami
{
	meta:
		Author = "@benkow_"
		Date = "2014/09/12"
		Description = "Strings inside"
		Reference = "http://www.kernelmode.info/forum/viewtopic.php?f=16&t=3483"
		description = "Detects strings related to the Linux Tsunami botnet"
		os = "linux"
		filetype = "executable"

	strings:
		$a = "PRIVMSG %s :[STD]Hitting %s"
		$b = "NOTICE %s :TSUNAMI <target> <secs>"
		$c = "NOTICE %s :I'm having a problem resolving my host, someone will have to SPOOFS me manually."

	condition:
		$a or $b or $c
}
