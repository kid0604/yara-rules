import "pe"

rule TurlaMosquito_Mal_4
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		date = "2018-02-22"
		hash1 = "b362b235539b762734a1833c7e6c366c1b46474f05dc17b3a631b3bff95a5eec"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <800KB and pe.imphash()=="17b328245e2874a76c2f46f9a92c3bad"
}
