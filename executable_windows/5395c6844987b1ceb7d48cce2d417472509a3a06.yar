rule IronTiger_GTalk_Trojan
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - GTalk Trojan"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "gtalklite.com" wide ascii
		$str2 = "computer=%s&lanip=%s&uid=%s&os=%s&data=%s" wide ascii
		$str3 = "D13idmAdm" wide ascii
		$str4 = "Error: PeekNamedPipe failed with %i" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}
