import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_WMIC_Downloader
{
	meta:
		author = "ditekSHen"
		description = "Detects files utilizing WMIC for whitelisting bypass and downloading second stage payloads"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WMIC.exe os get /format:\"http" wide
		$s2 = "WMIC.exe computersystem get /format:\"http" wide
		$s3 = "WMIC.exe dcomapp get /format:\"http" wide
		$s4 = "WMIC.exe desktop get /format:\"http" wide

	condition:
		( uint16(0)==0x004c or uint16(0)==0x5a4d) and 1 of them
}
