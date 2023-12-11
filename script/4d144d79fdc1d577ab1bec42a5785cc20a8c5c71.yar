import "pe"

rule APT_APT34_PS_Malware_Apr19_2
{
	meta:
		description = "Detects APT34 PowerShell malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
		date = "2019-04-17"
		hash1 = "2943e69e6c34232dee3236ced38d41d378784a317eeaf6b90482014210fcd459"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "= \"http://\" + [System.Net.Dns]::GetHostAddresses(\"" ascii
		$x2 = "$t = get-wmiobject Win32_ComputerSystemProduct  | Select-Object -ExpandProperty UUID" fullword ascii
		$x3 = "| Where { $_ -notmatch '^\\s+$' }" ascii
		$s1 = "= new-object System.Net.WebProxy($u, $true);" fullword ascii
		$s2 = " -eq \"dom\"){$" ascii
		$s3 = " -eq \"srv\"){$" ascii
		$s4 = "+\"<>\" | Set-Content" ascii

	condition:
		1 of ($x*) and 3 of them
}
