import "pe"

rule WiltedTulip_SilverlightMSI
{
	meta:
		description = "Detects powershell tool call Get_AD_Users_Logon_History used in Operation Wilted Tulip"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://www.clearskysec.com/tulip"
		date = "2017-07-23"
		hash1 = "c75906dbc3078ff81092f6a799c31afc79b1dece29db696b2ecf27951a86a1b2"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = ".\\Get_AD_Users_Logon_History.ps1 -MaxEvent" fullword ascii
		$x2 = "if ((Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly -ErrorAction \"SilentlyContinue\").Type -eq \"PTR\")" fullword ascii
		$x3 = "$Client_Name = (Resolve-dnsname $_.\"IP Address\" -Type PTR -TcpOnly -DnsOnly).NameHost  " fullword ascii
		$x4 = "########## Find the Computer account in AD and if not found, throw an exception ###########" fullword ascii

	condition:
		( filesize <20KB and 1 of them )
}
