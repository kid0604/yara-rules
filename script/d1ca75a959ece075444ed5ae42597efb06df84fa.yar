import "pe"

rule case_19530_systembc_s5
{
	meta:
		description = "file s5.ps1"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2024/02/26/seo-poisoning-to-domain-control-the-gootloader-saga-continues/"
		date = "2024-02-18"
		hash1 = "49b75f4f00336967f4bd9cbccf49b7f04d466bf19be9a5dec40d0c753189ea16"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Set-ItemProperty -Path $path_reg -Name \"socks_powershell\" -Value \"Powershell.exe -windowstyle hidden -ExecutionPolicy Bypass " ascii
		$x2 = "Set-ItemProperty -Path $path_reg -Name \"socks_powershell\" -Value \"Powershell.exe -windowstyle hidden -ExecutionPolicy Bypass " ascii
		$s3 = "Remove-ItemProperty -Path \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" -Name \"socks_powershell\"" fullword ascii
		$s4 = "$end = [int](Get-Date -uformat \"%s\")" fullword ascii
		$s5 = "$st = [int](Get-Date -uformat \"%s\")" fullword ascii
		$s6 = "$path_reg = \"HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\"" fullword ascii
		$s7 = "$sArray[0] = New-Object System.Net.Sockets.TcpClient( $ipaddress, $dport)" fullword ascii
		$s8 = "$sArray[$perem2] = New-Object System.Net.Sockets.TcpClient( $ip, $newport)" fullword ascii
		$s9 = "[string]$ip = [System.Text.Encoding]::ASCII.GetString($fB)" fullword ascii
		$s10 = "$ipaddress = '91.92.136.20'" fullword ascii
		$s11 = "$rc1 = [math]::Floor(($rc -band 0x0000ff00) * [math]::Pow(2,-8))" fullword ascii
		$s12 = "$o1 = [math]::Floor(($os -band 0x0000ff00) * [math]::Pow(2,-8))" fullword ascii
		$s13 = "$Time = $end - $st" fullword ascii
		$s14 = "elseif ($bf0[4 + 3] -eq 0x01 -as[byte])" fullword ascii
		$s15 = "$buff0[$start + $perem3] = $perem5 -as [byte]" fullword ascii
		$s16 = "Start-Sleep -s 180" fullword ascii
		$s17 = "[string]$ip = \"{0}.{1}.{2}.{3}\" -f $a, $b, $c, $ip" fullword ascii
		$s18 = "For ($i=0; $i -ne $perem9; $i++) { $bf0[$i + $perem0] = $rb[$i + $perem11] }" fullword ascii
		$s19 = "if ($bf0[2 + 0] -eq 0x00 -as[byte] -and $bf0[2 + 1] -eq 0x00 -as[byte])" fullword ascii
		$s20 = "if ($bf0[0 + 0] -eq 0x00 -as[byte] -and $bf0[0 + 1] -eq 0x00 -as[byte])" fullword ascii

	condition:
		uint16(0)==0x7824 and filesize <40KB and 1 of ($x*) and 4 of them
}
