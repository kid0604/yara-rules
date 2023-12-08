import "pe"

rule TurlaMosquito_Mal_5
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		date = "2018-02-22"
		hash1 = "26a1a42bc74e14887616f9d6048c17b1b4231466716a6426e7162426e1a08030"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <300KB and pe.imphash()=="ac40cf7479f53a4754ac6481a4f24e57"
}
