rule apt_RU_MoonlightMaze_customlokitools
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-15"
		version = "1.1"
		last_modified = "2017-03-22"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze Loki samples by custom attacker-authored strings"
		hash = "14cce7e641d308c3a177a8abb5457019"
		hash = "a3164d2bbc45fb1eef5fde7eb8b245ea"
		hash = "dabee9a7ea0ddaf900ef1e3e166ffe8a"
		hash = "1980958afffb6a9d5a6c73fc1e2795c2"
		hash = "e59f92aadb6505f29a9f368ab803082e"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$a1 = "Write file Ok..." ascii wide
		$a2 = "ERROR: Can not open socket...." ascii wide
		$a3 = "Error in parametrs:" ascii wide
		$a4 = "Usage: @<get/put> <IP> <PORT> <file>" ascii wide
		$a5 = "ERROR: Not connect..." ascii wide
		$a6 = "Connect successful...." ascii wide
		$a7 = "clnt <%d> rqstd n ll kll" ascii wide
		$a8 = "clnt <%d> rqstd swap" ascii wide
		$a9 = "cld nt sgnl prcs grp" ascii wide
		$a10 = "cld nt sgnl prnt" ascii wide
		$a11 = "ork error" ascii fullword

	condition:
		(( any of ($a*)))
}
