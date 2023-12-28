rule Lazarus_DreamJob_doc2021
{
	meta:
		description = "Malicious doc used in Lazarus operation Dream Job"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "ffec6e6d4e314f64f5d31c62024252abde7f77acdd63991cb16923ff17828885"
		hash2 = "8e1746829851d28c555c143ce62283bc011bbd2acfa60909566339118c9c5c97"
		hash3 = "294acafed42c6a4f546486636b4859c074e53d74be049df99932804be048f42c"
		os = "windows"
		filetype = "document"

	strings:
		$peheadb64 = "dCBiZSBydW4gaW4gRE9TIG1vZGU"
		$command1 = "cmd /c copy /b %systemroot%\\system32\\"
		$command2 = "Select * from Win32_Process where name"
		$command3 = "cmd /c explorer.exe /root"
		$command4 = "-decode"
		$command5 = "c:\\Drivers"
		$command6 = "explorer.exe"
		$command7 = "cmd /c md"
		$command8 = "cmd /c del"

	condition:
		uint16(0)==0xCFD0 and $peheadb64 and 4 of ($command*)
}
