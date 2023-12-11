import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_EXE_TransferSh_URL
{
	meta:
		author = "ditekSHen"
		description = "Detects images embedding based64-encoded executable, and a base64 marker"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "//transfer.sh/get/" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and 1 of them
}
