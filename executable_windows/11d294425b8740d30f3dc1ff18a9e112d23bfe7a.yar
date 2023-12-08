import "pe"

rule APT15_Malware_Mar18_MSExchangeTool
{
	meta:
		description = "Detects malware from APT 15 report by NCC Group"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/HZ5XMN"
		date = "2018-03-10"
		hash1 = "16b868d1bef6be39f69b4e976595e7bd46b6c0595cf6bc482229dbb9e64f1bce"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\Release\\EWSTEW.pdb" ascii
		$s2 = "EWSTEW.exe" fullword wide
		$s3 = "Microsoft.Exchange.WebServices.Data" fullword ascii
		$s4 = "tmp.dat" fullword wide
		$s6 = "/v or /t is null" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <40KB and all of them
}
