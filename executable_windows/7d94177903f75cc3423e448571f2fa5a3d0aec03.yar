import "pe"

rule MALWARE_Win_CryptoStealerGo
{
	meta:
		author = "ditekSHen"
		description = "CryptoStealerGo payload"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Go build ID: \"" ascii
		$s2 = "file_upload.go" ascii
		$s3 = "grequests.FileUpload" ascii
		$s4 = "runtime.newproc" ascii
		$s5 = "credit_cards" ascii
		$s6 = "zip.(*fileWriter).Write" ascii
		$s7 = "autofill_" ascii
		$s8 = "XFxVc2VyIERhdGFcXA==" ascii
		$s9 = "XFxBcHBEYXRhXFxMb2NhbFxc" ascii

	condition:
		uint16(0)==0x5a4d and 8 of them
}
