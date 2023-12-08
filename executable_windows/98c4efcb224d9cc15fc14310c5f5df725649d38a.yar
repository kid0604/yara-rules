import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_TelegramChatBot
{
	meta:
		author = "ditekSHen"
		description = "Detects executables using Telegram Chat Bot"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "https://api.telegram.org/bot" ascii wide
		$s2 = "/sendMessage?chat_id=" fullword ascii wide
		$s3 = "Content-Disposition: form-data; name=\"" fullword ascii
		$s4 = "/sendDocument?chat_id=" fullword ascii wide
		$p1 = "/sendMessage" ascii wide
		$p2 = "/sendDocument" ascii wide
		$p3 = "&chat_id=" ascii wide
		$p4 = "/sendLocation" ascii wide

	condition:
		uint16(0)==0x5a4d and (2 of ($s*) or (2 of ($p*) and 1 of ($s*)))
}
