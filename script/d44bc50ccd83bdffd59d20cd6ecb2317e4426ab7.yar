rule Empire_Invoke_EgressCheck
{
	meta:
		description = "Detects Empire component - file Invoke-EgressCheck.ps1"
		author = "Florian Roth"
		reference = "https://github.com/adaptivethreat/Empire"
		date = "2016-11-05"
		hash1 = "e2d270266abe03cfdac66e6fc0598c715e48d6d335adf09a9ed2626445636534"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "egress -ip $ip -port $c -delay $delay -protocol $protocol" fullword ascii

	condition:
		( uint16(0)==0x233c and filesize <10KB and 1 of them ) or all of them
}
