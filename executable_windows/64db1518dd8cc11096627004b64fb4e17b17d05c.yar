rule IronTiger_GetPassword_x64
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GetPassword x64"
		reference = "http://goo.gl/T5fSJC"
		modified = "2023-01-06"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "(LUID ERROR)" wide ascii
		$str2 = "Users\\K8team\\Desktop\\GetPassword" wide ascii
		$str3 = "Debug x64\\GetPassword.pdb" ascii
		$bla1 = "Authentication Package:" wide ascii
		$bla2 = "Authentication Domain:" wide ascii
		$bla3 = "* Password:" wide ascii
		$bla4 = "Primary User:" wide ascii

	condition:
		uint16(0)==0x5a4d and (( any of ($str*)) or ( all of ($bla*)))
}
