private rule priv02
{
	meta:
		date = "2018-02-10"
		author = "@unixfreaxjp"
		description = "Detects suspicious system calls and environment variables related to privilege escalation"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$vare01 = "socket" fullword nocase wide ascii
		$vare02 = "connect" fullword nocase wide ascii
		$vare03 = "alarm" fullword nocase wide ascii
		$vare04 = "dup2" fullword nocase wide ascii
		$vare05 = "execl" fullword nocase wide ascii
		$vare06 = "openpty" fullword nocase wide ascii
		$vare07 = "putenv" fullword nocase wide ascii
		$vare08 = "setsid" fullword nocase wide ascii
		$vare09 = "ttyname" fullword nocase wide ascii
		$vare00 = "waitpid" fullword nocase wide ascii
		$varc01 = "HISTFIL" fullword nocase wide ascii
		$varc02 = "TERML" fullword nocase wide ascii
		$varc03 = "/bin/sh" fullword nocase wide ascii

	condition:
		(5 of ($vare*) or (2 of ($varc*)))
}
