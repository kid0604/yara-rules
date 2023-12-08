rule sig_238_RunAsEx
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file RunAsEx.exe"
		author = "Florian Roth"
		date = "23.11.14"
		score = 60
		hash = "a22fa4e38d4bf82041d67b4ac5a6c655b2e98d35"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "RunAsEx By Assassin 2000. All Rights Reserved. http://www.netXeyes.com" fullword ascii
		$s8 = "cmd.bat" fullword ascii
		$s9 = "Note: This Program Can'nt Run With Local Machine." fullword ascii
		$s11 = "%s Execute Succussifully." fullword ascii
		$s12 = "winsta0" fullword ascii
		$s15 = "Usage: RunAsEx <UserName> <Password> <Execute File> [\"Execute Option\"]" fullword ascii

	condition:
		4 of them
}
