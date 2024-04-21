rule Locker_32
{
	meta:
		description = "Locker_32.dll"
		author = "_pete_0, TheDFIRReport"
		reference = "https://thedfirreport.com/2023/04/03/malicious-iso-file-leads-to-domain-wide-ransomware"
		date = "2023-04-02"
		hash1 = "A378B8E9173F4A5469E7B5105BE40723AF29CBD6EE00D3B13FF437DAE4514DFF"
		os = "windows"
		filetype = "executable"

	strings:
		$app1 = "plugin.dll" fullword ascii
		$app2 = "expand 32-byte k" fullword ascii
		$app3 = "FAST" wide ascii
		$app4 = "SLOW" wide ascii

	condition:
		uint16(0)==0x5A4D and filesize <100KB and all of ($app*)
}
