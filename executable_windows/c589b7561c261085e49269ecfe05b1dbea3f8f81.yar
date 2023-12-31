rule malware_windows_t3ntman_crunchrat
{
	meta:
		description = "HTTPS-based Remote Administration Tool (RAT)"
		reference = "https://github.com/t3ntman/CrunchRAT"
		author = "@mimeframe"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "<action>command<action>" wide ascii
		$a2 = "<action>upload<action>" wide ascii
		$a3 = "<action>download<action>" wide ascii
		$a4 = "cmd.exe" wide ascii
		$a5 = "application/x-www-form-urlencoded" wide ascii
		$a6 = "&action=" wide ascii
		$a7 = "&secondary=" wide ascii
		$a8 = "<secondary>" wide ascii
		$a9 = "<action>" wide ascii

	condition:
		all of ($a*)
}
