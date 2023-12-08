rule Backdoor_WebShell_asp : ASPXSpy
{
	meta:
		description = "Detect ASPXSpy"
		author = "xylitol@temari.fr"
		date = "2019-02-26"
		os = "windows"
		filetype = "script"

	strings:
		$string1 = "CmdShell" wide ascii
		$string2 = "ADSViewer" wide ascii
		$string3 = "ASPXSpy.Bin" wide ascii
		$string4 = "PortScan" wide ascii
		$plugin = "Test.AspxSpyPlugins" wide ascii

	condition:
		3 of ($string*) or $plugin
}
