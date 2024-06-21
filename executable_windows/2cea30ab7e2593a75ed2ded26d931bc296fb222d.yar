import "pe"

rule malware_webrcs_lnk
{
	meta:
		description = "lnk used to execute webrcs"
		author = "JPCERT/CC Incident Response Group"
		hash = "405b2933f2638767980171f3cb09e3f3ee598965d74dd5a041cac97e4e1b893d"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "'+$pid+'.dll';ni " ascii wide
		$s2 = "-I D;saps $f;cp desktop.ini " ascii wide
		$s3 = ";if(Test-Path $n){saps $" ascii wide

	condition:
		( uint32(0)==0x0000004C) and 2 of them
}
