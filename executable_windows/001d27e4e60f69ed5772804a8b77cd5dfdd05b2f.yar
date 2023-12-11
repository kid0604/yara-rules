rule MALW_trickbot_bankBot : Trojan
{
	meta:
		author = "Marc Salinas @Bondey_m"
		description = "Detects Trickbot Banking Trojan"
		os = "windows"
		filetype = "executable"

	strings:
		$str_trick_01 = "moduleconfig"
		$str_trick_02 = "Start"
		$str_trick_03 = "Control"
		$str_trick_04 = "FreeBuffer"
		$str_trick_05 = "Release"

	condition:
		all of ($str_trick_*)
}
