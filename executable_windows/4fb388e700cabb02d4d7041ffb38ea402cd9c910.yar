import "pe"

rule ME_Campaign_Malware_4
{
	meta:
		description = "Detects malware from Middle Eastern campaign reported by Talos"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
		date = "2018-02-07"
		hash1 = "c5bfb5118a999d21e9f445ad6ccb08eb71bc7bd4de9e88a41be9cf732156c525"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <1000KB and pe.imphash()=="fb7da233a35ac523d6059fff543627ab"
}
