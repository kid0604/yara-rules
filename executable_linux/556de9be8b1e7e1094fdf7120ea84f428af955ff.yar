rule apt_RU_MoonlightMaze_xk_keylogger
{
	meta:
		author = "Kaspersky Lab"
		date = "2017-03-27"
		version = "1.0"
		last_modified = "2017-03-27"
		reference = "https://en.wikipedia.org/wiki/Moonlight_Maze"
		description = "Rule to detect Moonlight Maze 'xk' keylogger"
		os = "linux"
		filetype = "executable"

	strings:
		$a1 = "Log ended at => %s"
		$a2 = "Log started at => %s [pid %d]"
		$a3 = "/var/tmp/task" fullword
		$a4 = "/var/tmp/taskhost" fullword
		$a5 = "my hostname: %s"
		$a6 = "/var/tmp/tasklog"
		$a7 = "/var/tmp/.Xtmp01" fullword
		$a8 = "myfilename=-%s-"
		$a9 = "/var/tmp/taskpid"
		$a10 = "mypid=-%d-" fullword
		$a11 = "/var/tmp/taskgid" fullword
		$a12 = "mygid=-%d-" fullword

	condition:
		((3 of ($a*)))
}
