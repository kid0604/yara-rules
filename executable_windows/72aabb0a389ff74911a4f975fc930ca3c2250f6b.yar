rule IronTiger_ChangePort_Toolkit_driversinstall
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Changeport Toolkit driverinstall"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "openmydoor" wide ascii
		$str2 = "Install service error" wide ascii
		$str3 = "start remove service" wide ascii
		$str4 = "NdisVersion" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}
