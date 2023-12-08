import "pe"

rule Imphash_UPX_Packed_Malware_1_TA17_293A
{
	meta:
		description = "Detects malware based on Imphash of malware used in TA17-293A"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		hash1 = "a278256fbf2f061cfded7fdd58feded6765fade730374c508adad89282f67d77"
		os = "windows"
		filetype = "executable"

	condition:
		( uint16(0)==0x5a4d and filesize <5000KB and pe.imphash()=="d7d745ea39c8c5b82d5e153d3313096c")
}
