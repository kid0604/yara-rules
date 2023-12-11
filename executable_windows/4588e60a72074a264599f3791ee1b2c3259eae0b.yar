import "pe"

rule ME_Campaign_Malware_5
{
	meta:
		description = "Detects malware from Middle Eastern campaign reported by Talos"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
		date = "2018-02-07"
		modified = "2022-08-18"
		hash1 = "d49e9fdfdce1e93615c406ae13ac5f6f68fb7e321ed4f275f328ac8146dd0fc1"
		hash2 = "e66af059f37bdd35056d1bb6a1ba3695fc5ce333dc96b5a7d7cc9167e32571c5"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "D:\\me\\do\\do\\obj\\" ascii
		$s2 = "Select * from Win32_ComputerSystem" fullword wide
		$s3 = "Get_Antivirus" fullword ascii
		$s4 = "{{\"id\":\"{0}\",\"user\":\"{1}\",\"path\":\"{2}\"}}" fullword wide
		$s5 = "update software online" fullword wide
		$s6 = "time.nist.gov" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <60KB and 5 of them or all of them
}
