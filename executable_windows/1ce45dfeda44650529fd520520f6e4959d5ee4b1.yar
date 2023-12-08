rule WildNeutron_Sample_9
{
	meta:
		description = "Wild Neutron APT Sample Rule - file 781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"
		author = "Florian Roth"
		reference = "https://securelist.com/blog/research/71275/wild-neutron-economic-espionage-threat-actor-returns-with-new-tricks/"
		date = "2015-07-10"
		score = 60
		hash = "781eb1e17349009fbae46aea5c59d8e5b68ae0b42335cb035742f6b0f4e4087e"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "http://get.adobe.com/flashplayer/" fullword wide
		$s1 = "xxxxxxxxxxxxxxxxxxxx" fullword wide
		$s4 = " Player Installer/Uninstaller" fullword wide
		$s5 = "Adobe Flash Plugin Updater" fullword wide
		$s6 = "uSOFTWARE\\Adobe" fullword wide
		$s11 = "2008R2" fullword wide
		$s12 = "%02d.%04d.%s" fullword wide
		$s13 = "%d -> %d" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <500KB and all of them
}
