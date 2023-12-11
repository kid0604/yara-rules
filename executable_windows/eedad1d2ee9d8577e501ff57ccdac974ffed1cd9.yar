import "pe"

rule Imphash_Malware_2_TA17_293A : HIGHVOL
{
	meta:
		description = "Detects malware based on Imphash of malware used in TA17-293A"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.us-cert.gov/ncas/alerts/TA17-293A"
		date = "2017-10-21"
		os = "windows"
		filetype = "executable"

	condition:
		( uint16(0)==0x5a4d and filesize <5000KB and pe.imphash()=="a8f69eb2cf9f30ea96961c86b4347282")
}
