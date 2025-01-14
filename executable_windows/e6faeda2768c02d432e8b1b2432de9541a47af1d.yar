import "pe"

rule MALWARE_Win_FakeCaptcha_Downloader
{
	meta:
		author = "ditekshen"
		description = "Detects downloader executables dropped by fake captcha"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "</script>MZ" ascii
		$s2 = "window.close();" ascii
		$s3 = "eval(" ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
