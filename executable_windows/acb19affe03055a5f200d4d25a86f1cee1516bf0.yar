rule WildNeutron_javacpl
{
	meta:
		description = "Wild Neutron APT Sample Rule - from files 683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9, 758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92, 8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		super_rule = 1
		hash1 = "683f5b476f8ffe87ec22b8bab57f74da4a13ecc3a5c2cbf951999953c2064fc9"
		hash2 = "758e6b519f6c0931ff93542b767524fc1eab589feb5cfc3854c77842f9785c92"
		hash3 = "8ca7ed720babb32a6f381769ea00e16082a563704f8b672cb21cf11843f4da7a"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "javacpl.exe" fullword wide
		$s0 = "RunFile: couldn't find ShellExecuteExA/W in SHELL32.DLL!" fullword ascii
		$s1 = "Error executing CreateProcess()!!" fullword wide
		$s2 = "http://www.java.com/en/download/installed.jsp?detect=jre" fullword ascii
		$s3 = "RunFile: couldn't load SHELL32.DLL!" fullword ascii
		$s4 = "Process is not running any more" fullword wide
		$s6 = "Windows NT Version %lu.%lu" fullword wide
		$s7 = "Usage: destination [reference]" fullword wide
		$s8 = "Invalid input handle!!!" fullword ascii
		$s9 = ".com;.exe;.bat;.cmd" fullword wide
		$s10 = ") -%s-> %s (" fullword ascii
		$s11 = "cmdextversion" fullword wide
		$s12 = "Invalid pid (%s)" fullword wide
		$s13 = "\"%s\" /K %s" fullword wide
		$s14 = "Error setting %s (%s)" fullword wide
		$s16 = "cmdcmdline" fullword wide
		$s39 = "2008R2" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1677KB and all of them
}
