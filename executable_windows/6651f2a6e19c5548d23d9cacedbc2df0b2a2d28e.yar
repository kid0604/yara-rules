import "pe"

rule MALWARE_Win_QuiteRAT
{
	meta:
		author = "ditekSHen"
		description = "Detects QuiteRAT"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "< No Pineapple! >" ascii
		$x2 = ".?AVPineapple" ascii
		$x3 = ".?AVApple@@" ascii
		$s1 = "XgsdCwsRFxZF" ascii
		$s2 = "XggZChkVRQ==" ascii
		$s3 = "RxUZERQRHEU=" ascii
		$s4 = "XhkbDBEXFkU" ascii

	condition:
		uint16(0)==0x5a4d and (( all of ($x*) and 1 of ($s*)) or (1 of ($x*) and 3 of ($s*)))
}
