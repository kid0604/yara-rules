import "pe"

rule MALWARE_Win_DLInjector06
{
	meta:
		author = "ditekSHen"
		description = "Detects downloader / injector"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/74.0.3729.169 Safari/537.36" ascii wide
		$s2 = "Content-Type: application/x-www-form-urlencoded" wide
		$s3 = "https://ipinfo.io/" wide
		$s4 = "https://db-ip.com/" wide
		$s5 = "https://www.maxmind.com/en/locate-my-ip-address" wide
		$s6 = "https://ipgeolocation.io/" wide
		$s7 = "POST" fullword wide

	condition:
		uint16(0)==0x5a4d and all of them
}
