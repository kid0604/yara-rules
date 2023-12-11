rule IronTiger_PlugX_Server
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX Server"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "\\UnitFrmManagerKeyLog.pas" wide ascii
		$str2 = "\\UnitFrmManagerRegister.pas" wide ascii
		$str3 = "Input Name..." wide ascii
		$str4 = "New Value#" wide ascii
		$str5 = "TThreadRControl.Execute SEH!!!" wide ascii
		$str6 = "\\UnitFrmRControl.pas" wide ascii
		$str7 = "OnSocket(event is error)!" wide ascii
		$str8 = "Make 3F Version Ok!!!" wide ascii
		$str9 = "PELEASE DO NOT CHANGE THE DOCAMENT" wide ascii
		$str10 = "Press [Ok] Continue Run, Press [Cancel] Exit" wide ascii

	condition:
		uint16(0)==0x5a4d and (2 of ($str*))
}
