import "pe"

rule WaterBug_turla_dll
{
	meta:
		description = "Symantec Waterbug Attack - Trojan Turla DLL"
		author = "Symantec Security Response"
		date = "22.01.2015"
		reference = "http://www.symantec.com/connect/blogs/turla-spying-tool-targets-governments-and-diplomats"
		os = "windows"
		filetype = "executable"

	strings:
		$a = /([A-Za-z0-9]{2,10}_){,2}Win32\.dll\x00/

	condition:
		pe.exports("ee") and $a
}
