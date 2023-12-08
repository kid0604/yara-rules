rule Msfpayloads_msf_7
{
	meta:
		description = "Metasploit Payloads - file msf.vba"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-02-09"
		hash1 = "425beff61a01e2f60773be3fcb74bdfc7c66099fe40b9209745029b3c19b5f2f"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Private Declare PtrSafe Function CreateThread Lib \"kernel32\" (ByVal" ascii
		$s2 = "= VirtualAlloc(0, UBound(Tsw), &H1000, &H40)" fullword ascii
		$s3 = "= RtlMoveMemory(" ascii

	condition:
		all of them
}
