import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_RawGitHub_URL
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing URLs to raw contents of a Github gist"
		os = "windows"
		filetype = "executable"

	strings:
		$url1 = "https://gist.githubusercontent.com/" ascii wide
		$url2 = "https://raw.githubusercontent.com/" ascii wide
		$raw = "/raw/" ascii wide

	condition:
		uint16(0)==0x5a4d and (($url1 and $raw) or ($url2))
}
