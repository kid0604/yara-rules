import "pe"

rule TurlaMosquito_Mal_2
{
	meta:
		description = "Detects malware sample from Turla Mosquito report"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.welivesecurity.com/wp-content/uploads/2018/01/ESET_Turla_Mosquito.pdf"
		date = "2018-02-22"
		hash1 = "68c6e9dea81f082601ae5afc41870cea3f71b22bfc19bcfbc61d84786e481cb4"
		hash2 = "05254971fe3e1ca448844f8cfcfb2b0de27e48abd45ea2a3df897074a419a3f4"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = ".?AVFileNameParseException@ExecuteFile@@" fullword ascii
		$s3 = "no_address" fullword wide
		$s6 = "SRRRQP" fullword ascii
		$s7 = "QWVPQQ" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <600KB and (pe.imphash()=="cd918073f209c5da7a16b6c125d73746" or all of them )
}
