rule win_private_profile
{
	meta:
		author = "x0r"
		description = "Affect private profile"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "kernel32.dll" nocase
		$c1 = "GetPrivateProfileIntA"
		$c2 = "GetPrivateProfileStringA"
		$c3 = "WritePrivateProfileStringA"

	condition:
		$f1 and 1 of ($c*)
}
