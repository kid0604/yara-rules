rule IronTiger_ChangePort_Toolkit_ChangePortExe
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Toolkit ChangePort"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "Unable to alloc the adapter!" wide ascii
		$str2 = "Wait for master fuck" wide ascii
		$str3 = "xx.exe <HOST> <PORT>" wide ascii
		$str4 = "chkroot2007" wide ascii
		$str5 = "Door is bind on %s" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}
