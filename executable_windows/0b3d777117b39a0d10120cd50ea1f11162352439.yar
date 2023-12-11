import "pe"

rule Anthem_DeepPanda_Trojan_Kakfum
{
	meta:
		description = "Anthem Hack Deep Panda - Trojan.Kakfum sqlsrv32.dll"
		author = "Florian Roth"
		date = "2015/02/08"
		hash1 = "ab58b6aa7dcc25d8f6e4b70a24e0ccede0d5f6129df02a9e61293c1d7d7640a2"
		hash2 = "c6c3bb72896f8f0b9a5351614fd94e889864cf924b40a318c79560bbbcfa372f"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "%SystemRoot%\\System32\\svchost.exe -k sqlserver" fullword ascii
		$s1 = "%s\\sqlsrv32.dll" fullword ascii
		$s2 = "%s\\sqlsrv64.dll" fullword ascii
		$s3 = "%s\\%d.tmp" fullword ascii
		$s4 = "ServiceMaix" fullword ascii
		$s15 = "sqlserver" fullword ascii

	condition:
		all of them
}
