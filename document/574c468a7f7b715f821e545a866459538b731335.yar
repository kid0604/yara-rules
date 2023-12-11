import "math"
import "pe"

rule APT_APT29_NOBELIUM_BoomBox_PDF_Masq_May21_1
{
	meta:
		description = "Detects PDF documents as used by BoomBox as described in APT29 NOBELIUM report"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/05/27/new-sophisticated-email-based-attack-from-nobelium/"
		date = "2021-05-27"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "document"

	strings:
		$ah1 = { 25 50 44 46 2d 31 2e 33 0a 25 }
		$af1 = { 0a 25 25 45 4f 46 0a }
		$fp1 = "endobj" ascii
		$fp2 = "endstream" ascii
		$fp3 = { 20 6F 62 6A 0A }

	condition:
		$ah1 at 0 and $af1 at ( filesize -7) and filesize <100KB and not 1 of ($fp*) and math.entropy(16, filesize )>7
}
