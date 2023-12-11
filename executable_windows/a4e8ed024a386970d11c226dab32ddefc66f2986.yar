rule WildNeutron_Sample_8
{
	meta:
		description = "Wild Neutron APT Sample Rule - file 758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "RunFile: couldn't load SHELL32.DLL!" fullword ascii
		$x2 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii
		$x3 = "Error executing CreateProcess()!!" fullword wide
		$x4 = "cmdcmdline" fullword wide
		$x5 = "Invalid input handle!!!" fullword ascii
		$s1 = "Process %d terminated" fullword wide
		$s2 = "Process is not running any more" fullword wide
		$s3 = "javacpl.exe" fullword wide
		$s4 = "Windows NT Version %lu.%lu" fullword wide
		$s5 = "Usage: destination [reference]" fullword wide
		$s6 = ".com;.exe;.bat;.cmd" fullword wide
		$s7 = ") -%s-> %s (" fullword ascii
		$s8 = "cmdextversion" fullword wide
		$s9 = "Invalid pid (%s)" fullword wide
		$s10 = "\"%s\" /K %s" fullword wide
		$s11 = "Error setting %s (%s)" fullword wide
		$s12 = "DEBUG: Cannot allocate memory for ptrNextNode->ptrNext!" fullword ascii
		$s13 = "Failed to build full directory path" fullword wide
		$s14 = "DEBUG: Cannot allocate memory for ptrFileArray!" fullword ascii
		$s15 = "%-8s %-3s  %*s %s  %s" fullword wide
		$s16 = " %%%c in (%s) do " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1677KB and 2 of ($x*) and 6 of ($s*)
}
