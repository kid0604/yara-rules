import "pe"

rule MALWARE_Win_HUNT_GhostEmperor_RemoteControlPayload
{
	meta:
		author = "ditekSHen"
		description = "Attempt on hunting GhostEmperor Stage 4 Remote Control Payload"
		reference = "https://media.kasperskycontenthub.com/wp-content/uploads/sites/43/2021/09/30094337/GhostEmperor_technical-details_PDF_eng.pdf"
		os = "windows"
		filetype = "executable"

	condition:
		uint16(0)==0x5a4d and pe.is_dll() and pe.number_of_exports==2 and pe.exports("1") and pe.exports("__acrt_iob_func")
}
