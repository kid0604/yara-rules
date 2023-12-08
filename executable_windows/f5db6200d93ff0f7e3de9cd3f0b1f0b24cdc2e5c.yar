rule IronTiger_HTTPBrowser_Dropper
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - HTTPBrowser Dropper"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = ".dllUT" nocase wide ascii
		$str2 = ".exeUT" nocase wide ascii
		$str3 = ".urlUT" nocase wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}
