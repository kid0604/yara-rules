rule IronTiger_Ring_Gh0stvariant
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - Ring Gh0stvariant"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "RING RAT Exception" wide ascii
		$str2 = "(can not update server recently)!" wide ascii
		$str4 = "CreaetProcess Error" wide ascii
		$bla1 = "Sucess!" wide ascii
		$bla2 = "user canceled!" wide ascii

	condition:
		uint16(0)==0x5a4d and (( any of ($str*)) or ( all of ($bla*)))
}
