rule IronTiger_ReadPWD86
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - ReadPWD86"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "Fail To Load LSASRV" wide ascii
		$str2 = "Fail To Search LSASS Data" wide ascii
		$str3 = "User Principal" wide ascii

	condition:
		uint16(0)==0x5a4d and ( all of ($str*))
}
