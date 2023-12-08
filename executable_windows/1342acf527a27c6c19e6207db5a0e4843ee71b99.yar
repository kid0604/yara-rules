import "pe"

rule ME_Campaign_Malware_1
{
	meta:
		description = "Detects malware from Middle Eastern campaign reported by Talos"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2018/02/targeted-attacks-in-middle-east.html"
		date = "2018-02-07"
		hash1 = "1176642841762b3bc1f401a5987dc55ae4b007367e98740188468642ffbd474e"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <5000KB and (pe.imphash()=="618f76eaf4bd95c690d43e84d617efe9")
}
