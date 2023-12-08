private rule is__str_Rebirth_gen3
{
	meta:
		description = "Generic detection for Vulcan branch Rebirth or Katrina from Torlus nextgen"
		reference = "https://imgur.com/a/SSKmu"
		reference = "https://www.reddit.com/r/LinuxMalware/comments/7rprnx/vulcan_aka_linuxrebirth_or_katrina_variant_of/"
		author = "unixfreaxjp"
		org = "MalwareMustDie"
		date = "2018-01-21"
		os = "linux"
		filetype = "script"

	strings:
		$str01 = "/usr/bin/python" fullword nocase wide ascii
		$str02 = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n" fullword nocase wide ascii
		$str03 = "Telnet Range %d->%d" fullword nocase wide ascii
		$str04 = "Mirai Range %d->%d" fullword nocase wide ascii
		$str05 = "[Updating] [%s:%s]" fullword nocase wide ascii
		$str06 = "rm -rf /tmp/* /var/* /var/run/* /var/tmp/*" fullword nocase wide ascii
		$str07 = "\x1B[96m[DEVICE] \x1B[97mConnected" fullword nocase wide ascii

	condition:
		4 of them
}
