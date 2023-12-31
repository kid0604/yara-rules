rule malware_macos_neoneggplant_eggshell
{
	meta:
		description = "EggShell is an iOS and macOS post exploitation surveillance pentest tool written in Python."
		reference = "https://github.com/neoneggplant/EggShell"
		author = "@mimeframe"
		os = "macos,ios"
		filetype = "script"

	strings:
		$a1 = "Created By Lucas Jackson (@neoneggplant)" wide ascii
		$a2 = "SET LHOST (Leave blank for" wide ascii
		$a3 = "SET LPORT (Leave blank for" wide ascii
		$b1 = "/tmp/.esplog" wide ascii
		$b2 = "spGHbigdxMBJpbOCAr3rnS3inCdYQyZV" wide ascii
		$b3 = "keylogclear" wide ascii
		$b4 = "getpasscode" wide ascii
		$c1 = "spGHbigdxMBJpbOCAr3rnS3inCdYQyZV" wide ascii
		$c2 = "getfacebook" wide ascii
		$c3 = "type is eggsu" wide ascii
		$c4 = "rmpersistence" wide ascii

	condition:
		all of ($a*) or 3 of ($b*) or 3 of ($c*)
}
