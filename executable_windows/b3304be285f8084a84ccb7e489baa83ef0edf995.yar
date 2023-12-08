import "pe"

rule APT_Winnti_MAL_Dec19_2
{
	meta:
		description = "Detects Winnti malware"
		author = "Unknown"
		reference = "https://www.verfassungsschutz.de/download/broschuere-2019-12-bfv-cyber-brief-2019-01.pdf"
		date = "2019-12-06"
		score = 75
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "IPSecMiniPort" wide fullword
		$a2 = "ndis6fw" wide fullword
		$a3 = "TCPIP" wide fullword
		$a4 = "NDIS.SYS" ascii fullword
		$a5 = "ntoskrnl.exe" ascii fullword
		$a6 = "\\BaseNamedObjects\\{B2B87CCA-66BC-4C24-89B2-C23C9EAC2A66}" wide
		$a7 = "\\Device\\Null" wide
		$a8 = "\\Device" wide
		$a9 = "\\Driver" wide
		$b1 = { 66 81 7? ?? 70 17 }
		$b2 = { 81 7? ?? 07 E0 15 00 }
		$b3 = { 8B 46 18 3D 03 60 15 00 }

	condition:
		(6 of ($a*)) and (2 of ($b*))
}
