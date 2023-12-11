rule EQGRP_pandarock
{
	meta:
		description = "EQGRP Toolset Firewall - from files pandarock_v1.11.1.1.bin, pit"
		author = "Florian Roth"
		reference = "Research"
		date = "2016-08-16"
		super_rule = 1
		hash1 = "1214e282ac7258e616ebd76f912d4b2455d1b415b7216823caa3fc0d09045a5f"
		hash2 = "c8a151df7605cb48feb8be2ab43ec965b561d2b6e2a837d645fdf6a6191ab5fe"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "* Not attempting to execute \"%s\" command" fullword ascii
		$x2 = "TERMINATING SCRIPT (command error or \"quit\" encountered)" fullword ascii
		$x3 = "execute code in <file> passing <argX> (HEX)" fullword ascii
		$x4 = "* Use arrow keys to scroll through command history" fullword ascii
		$s1 = "pitCmd_processCmdLine" fullword ascii
		$s2 = "execute all commands in <file>" fullword ascii
		$s3 = "__processShellCmd" fullword ascii
		$s4 = "pitTarget_getDstPort" fullword ascii
		$s5 = "__processSetTargetIp" fullword ascii
		$o1 = "Logging commands and output - ON" fullword ascii
		$o2 = "This command is too dangerous.  If you'd like to run it, contact the development team" fullword ascii

	condition:
		( uint16(0)==0x457f and filesize <3000KB and 1 of ($x*)) or (4 of them ) or 1 of ($o*)
}
