rule Atmos_Malware
{
	meta:
		description = "Generic Spyware.Citadel.Atmos Signature"
		author = "xylitol@temari.fr"
		reference = "http://www.xylibox.com/2016/02/citadel-0011-atmos.html"
		date = "20/08/2016"
		os = "windows"
		filetype = "executable"

	strings:
		$MZ = {4D 5A}
		$LKEY = "533D9226E4C1CE0A9815DBEB19235AE4" wide ascii
		$TS1 = "X-TS-Rule-Name: %s" wide ascii
		$TS2 = "X-TS-Rule-PatternID: %u" wide ascii
		$TS3 = "X-TS-BotID: %s" wide ascii
		$TS4 = "X-TS-Domain: %s" wide ascii
		$TS5 = "X-TS-SessionID: %s" wide ascii
		$TS6 = "X-TS-Header-Cookie: %S" wide ascii
		$TS7 = "X-TS-Header-Referer: %S" wide ascii
		$TS8 = "X-TS-Header-AcceptEncoding: %S" wide ascii
		$TS9 = "X-TS-Header-AcceptLanguage: %S" wide ascii
		$TS10 = "X-TS-Header-UserAgent: %S" wide ascii
		$VNC1 = "_hvnc_init@4" wide ascii
		$VNC2 = "_hvnc_uninit@0" wide ascii
		$VNC3 = "_hvnc_start@8" wide ascii
		$VNC4 = "_hvnc_stop@0" wide ascii
		$VNC5 = "_hvnc_wait@0" wide ascii
		$VNC6 = "_hvnc_work@0" wide ascii
		$WB1 = "nspr4.dll" wide ascii
		$WB2 = "nss3.dll" wide ascii
		$WB3 = "chrome.dll" wide ascii
		$WB4 = "Internet Explorer" wide ascii
		$WB5 = "Firefox" wide ascii
		$WB6 = "Chrome" wide ascii

	condition:
		($MZ at 0 and $LKEY) and ((5 of ($TS*) and all of ($WB*)) or (3 of ($VNC*) and all of ($WB*))) and filesize <300KB
}
