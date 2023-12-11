import "pe"

rule OilRig_Malware_Campaign_Gen2
{
	meta:
		description = "Detects Oilrig malware samples"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/QMRZ8K"
		date = "2016-10-12"
		modified = "2023-01-07"
		hash1 = "c6437f57a8f290b5ec46b0933bfa8a328b0cb2c0c7fbeea7f21b770ce0250d3d"
		hash2 = "293522e83aeebf185e653ac279bba202024cedb07abc94683930b74df51ce5cb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%userprofile%\\AppData\\Local\\Microsoft\\" ascii
		$s2 = "$fdn=[System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String('" fullword ascii
		$s3 = "&{$rn = Get-Random; $id = 'TR" fullword ascii
		$s4 = "') -replace '__',('DNS'+$id) | " fullword ascii
		$s5 = "\\upd.vbs" ascii
		$s6 = "schtasks /create /F /sc minute /mo " fullword ascii
		$s7 = "') -replace '__',('HTP'+$id) | " fullword ascii
		$s8 = "&{$rn = Get-Random -minimum 1 -maximum 10000; $id = 'AZ" fullword ascii
		$s9 = "http://www.israirairlines.com/?mode=page&page=14635&lang=eng<" fullword ascii

	condition:
		( uint16(0)==0xcfd0 and filesize <4000KB and 2 of ($s*)) or (4 of them )
}
