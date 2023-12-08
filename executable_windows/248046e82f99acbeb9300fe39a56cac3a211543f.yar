import "pe"

rule Win32OPCHavex
{
	meta:
		Author = "BAE Systems"
		Date = "2014/06/23"
		Description = "Rule for identifying OPC version of HAVEX"
		Reference = "www.f-secure.com/weblog/archives/00002718.html"
		description = "Identifies OPC version of HAVEX"
		os = "windows"
		filetype = "executable"

	strings:
		$mzhdr = "MZ"
		$dll = "7CFC52CD3F87.dll"
		$a1 = "Start finging of LAN hosts..." wide
		$a2 = "Finding was fault. Unexpective error" wide
		$a3 = "Was found %i hosts in LAN:" wide
		$a4 = "Hosts was't found." wide
		$a5 = "Start finging of OPC Servers..." wide
		$a6 = "Was found %i OPC Servers." wide
		$a7 = "OPC Servers not found. Programm finished" wide
		$a8 = "%s[%s]!!!EXEPTION %i!!!" wide
		$a9 = "Start finging of OPC Tags..." wide

	condition:
		$mzhdr at 0 and ($dll or ( any of ($a*)))
}
