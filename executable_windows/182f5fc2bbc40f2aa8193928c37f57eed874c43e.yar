import "pe"

rule PasswordsPro
{
	meta:
		description = "Auto-generated rule - file PasswordsPro.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "PasswordPro"
		date = "2017-08-27"
		hash1 = "5b3d6654e6d9dc49ee1136c0c8e8122cb0d284562447abfdc05dfe38c79f95bf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "No users marked for attack or all marked users already have passwords found!" fullword ascii
		$s2 = "%s\\PasswordsPro.ini.Dictionaries(%d)" fullword ascii
		$s3 = "Passwords processed since attack start:" fullword ascii

	condition:
		( uint16(0)==0x5a4d and filesize <2000KB and 1 of them )
}
