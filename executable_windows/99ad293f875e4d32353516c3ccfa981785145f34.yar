rule Angry_IP_Scanner_v2_08_ipscan
{
	meta:
		description = "Auto-generated rule on file ipscan.exe"
		author = "yarGen Yara Rule Generator by Florian Roth"
		hash = "70cf2c09776a29c3e837cb79d291514a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "_H/EnumDisplay/"
		$s5 = "ECTED.MSVCRT0x"
		$s8 = "NotSupported7"

	condition:
		all of them
}
