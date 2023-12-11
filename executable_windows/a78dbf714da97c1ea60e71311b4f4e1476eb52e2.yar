import "pe"

rule KeyBoy_InstallClient
{
	meta:
		description = "Detects KeyBoy InstallClient"
		author = "Markus Neis, Florian Roth"
		reference = "https://blog.trendmicro.com/trendlabs-security-intelligence/tropic-trooper-new-strategy/"
		date = "2018-03-26"
		hash1 = "85d32cb3ae046a38254b953a00b37bb87047ec435edb0ce359a867447ee30f8b"
		hash2 = "b0f120b11f727f197353bc2c98d606ed08a06f14a1c012d3db6fe0a812df528a"
		hash1 = "d65f809f7684b28a6fa2d9397582f350318027999be3acf1241ff44d4df36a3a"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "egsvr32.exe \"/u bitsadmin /canceft\\windows\\currebitsadmin" ascii
		$x2 = "/addfibitsadmin /Resumbitsadmin /SetNosoftware\\microsotifyCmdLine " ascii
		$x3 = "D:\\Work\\Project\\VS\\house\\Apple\\" ascii
		$x4 = "Bj+I11T6z9HFMG5Z5FMT/u62z9zw8FyWV0xrcK7HcYXkiqnAy5tc/iJuKtwM8CT3sFNuQu8xDZQGSR6D8/Bc/Dpuz8gMJFz+IrYqNAzwuPIitg==" fullword ascii
		$x5 = "szCmd1:%s" fullword ascii
		$s1 = "cmd.exe /c \"%s\"" fullword ascii
		$s4 = "rundll32.exe %s Main" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and (1 of ($x*) or 2 of them )
}
