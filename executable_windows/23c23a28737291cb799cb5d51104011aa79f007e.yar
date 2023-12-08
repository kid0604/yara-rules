rule MALW_mailsercher_trickbot_module : Trojan
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = " Detects mailsearcher module from Trickbot Trojan"
		os = "windows"
		filetype = "executable"

	strings:
		$str_mails_01 = "mailsearcher"
		$str_mails_02 = "handler"
		$str_mails_03 = "conf"
		$str_mails_04 = "ctl"
		$str_mails_05 = "SetConf"
		$str_mails_06 = "file"
		$str_mails_07 = "needinfo"
		$str_mails_08 = "mailconf"

	condition:
		all of ($str_mails_*)
}
