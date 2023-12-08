rule IronTiger_PlugX_FastProxy
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX FastProxy"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "SAFEPROXY HTServerTimer Quit!" wide ascii
		$str2 = "Useage: %s pid" wide ascii
		$str3 = "%s PORT[%d] TO PORT[%d] SUCCESS!" wide ascii
		$str4 = "p0: port for listener" wide ascii
		$str5 = "\\users\\whg\\desktop\\plug\\" wide ascii
		$str6 = "[+Y] cwnd : %3d, fligth:" wide ascii

	condition:
		uint16(0)==0x5a4d and ( any of ($str*))
}
