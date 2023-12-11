import "pe"

rule APT_APT34_PS_Malware_Apr19_1
{
	meta:
		description = "Detects APT34 PowerShell malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/0xffff0800/status/1118406371165126656"
		date = "2019-04-17"
		hash1 = "b1d621091740e62c84fc8c62bcdad07873c8b61b83faba36097ef150fd6ec768"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "= get-wmiobject Win32_ComputerSystemProduct  | Select-Object -ExpandProperty UUID" ascii
		$x2 = "Write-Host \"excepton occured!\"" ascii
		$s1 = "Start-Sleep -s 1;" fullword ascii
		$s2 = "Start-Sleep -m 100;" fullword ascii

	condition:
		1 of ($x*) or 2 of them
}
