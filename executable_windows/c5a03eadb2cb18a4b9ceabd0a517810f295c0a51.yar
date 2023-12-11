rule MALW_dllinject_trickbot_module : Trojan
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = " Detects dllinject module from Trickbot Trojan"
		os = "windows"
		filetype = "executable"

	strings:
		$str_dllinj_01 = "user_pref("
		$str_dllinj_02 = "<ignore_mask>"
		$str_dllinj_03 = "<require_header>"
		$str_dllinj_04 = "</dinj>"

	condition:
		all of ($str_dllinj_*)
}
