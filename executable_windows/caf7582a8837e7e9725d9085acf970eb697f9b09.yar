rule IronTiger_PlugX_DosEmulator_alt_1
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "Iron Tiger Malware - PlugX DosEmulator"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "Dos Emluator Ver" nocase wide ascii
		$str2 = "\\PIPE\\FASTDOS" nocase wide ascii
		$str3 = "FastDos.cpp" nocase wide ascii
		$str4 = "fail,error code = %d." nocase wide ascii

	condition:
		uint16(0)==0x5a4d and ( any of ($str*))
}
