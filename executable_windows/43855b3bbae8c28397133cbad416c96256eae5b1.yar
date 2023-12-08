import "pe"

rule Freeenki_Infostealer_Nov17_Export_Sig_Testing
{
	meta:
		description = "Detects Freenki infostealer malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/11/ROKRAT-Reloaded.html"
		date = "2017-11-28"
		hash1 = "99c1b4887d96cb94f32b280c1039b3a7e39ad996859ffa6dd011cf3cca4f1ba5"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and filesize <3000KB and pe.exports("getUpdate") and pe.number_of_exports==1
}
