rule malware_macos_marten4n6_evilosx
{
	meta:
		description = "EvilOSX is a pure python, post-exploitation, RAT (Remote Administration Tool) for macOS / OSX."
		reference = "https://github.com/Marten4n6/EvilOSX"
		author = "@mimeframe"
		os = "macos"
		filetype = "script"

	strings:
		$a1 = "icloud_phish_stop" fullword wide ascii
		$a2 = "icloud_contacts" fullword wide ascii
		$a3 = "itunes_backups" fullword wide ascii
		$a4 = "chrome_passwords" fullword wide ascii
		$a5 = "Starting EvilOSX..." wide ascii

	condition:
		4 of ($a*)
}
