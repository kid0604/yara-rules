rule MALW_systeminfo_trickbot_module : Trojan
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "Detects systeminfo module from Trickbot Trojan"
		os = "windows"
		filetype = "executable"

	strings:
		$str_systeminf_01 = "<program>"
		$str_systeminf_02 = "<service>"
		$str_systeminf_03 = "</systeminfo>"
		$str_systeminf_04 = "GetSystemInfo.pdb"
		$str_systeminf_05 = "</autostart>"
		$str_systeminf_06 = "</moduleconfig>"

	condition:
		all of ($str_systeminf_*)
}
