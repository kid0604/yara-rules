rule LinuxHacktool_eyes_screen
{
	meta:
		description = "Linux hack tools - file screen"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "a240a0118739e72ff89cefa2540bf0d7da8f8a6c"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "or: %s -r [host.tty]" fullword ascii
		$s1 = "%s: process: character, ^x, or (octal) \\032 expected." fullword ascii
		$s2 = "Type \"screen [-d] -r [pid.]tty.host\" to resume one of them." fullword ascii
		$s6 = "%s: at [identifier][%%|*|#] command [args]" fullword ascii
		$s8 = "Slurped only %d characters (of %d) into buffer - try again" fullword ascii
		$s11 = "command from %s: %s %s" fullword ascii
		$s16 = "[ Passwords don't match - your armor crumbles away ]" fullword ascii
		$s19 = "[ Passwords don't match - checking turned off ]" fullword ascii

	condition:
		all of them
}
