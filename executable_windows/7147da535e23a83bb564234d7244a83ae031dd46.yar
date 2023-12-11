rule IronTiger_GetUserInfo
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GetUserInfo"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "getuserinfo username" nocase wide ascii
		$str2 = "joe@joeware.net" nocase wide ascii
		$str3 = "If . specified for userid," nocase wide ascii

	condition:
		uint16(0)==0x5a4d and ( any of ($str*))
}
