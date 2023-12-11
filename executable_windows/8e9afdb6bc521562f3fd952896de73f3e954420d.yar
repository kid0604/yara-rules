rule IronPanda_Malware1
{
	meta:
		description = "Iron Panda Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/E4qia9"
		date = "2015-09-16"
		hash = "a0cee5822ddf254c254a5a0b7372c9d2b46b088a254a1208cb32f5fe7eca848a"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "activedsimp.dll" fullword wide
		$s1 = "get_BadLoginAddress" fullword ascii
		$s2 = "get_LastFailedLogin" fullword ascii
		$s3 = "ADS_UF_ENCRYPTED_TEXT_PASSWORD_ALLOWED" fullword ascii
		$s4 = "get_PasswordExpirationDate" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
