rule IronTiger_dllshellexc2010
{
	meta:
		author = "Cyber Safety Solutions, Trend Micro"
		description = "dllshellexc2010 Exchange backdoor + remote shell"
		reference = "http://goo.gl/T5fSJC"
		os = "windows"
		filetype = "executable"

	strings:
		$str1 = "Microsoft.Exchange.Clients.Auth.dll" ascii wide
		$str2 = "Dllshellexc2010" wide ascii
		$str3 = "Users\\ljw\\Documents" wide ascii
		$bla1 = "please input path" wide ascii
		$bla2 = "auth.owa" wide ascii

	condition:
		( uint16(0)==0x5a4d) and (( any of ($str*)) or ( all of ($bla*)))
}
