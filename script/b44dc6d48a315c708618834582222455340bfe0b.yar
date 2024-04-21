rule case_19772_anydesk_id_tool
{
	meta:
		description = "19772 - file GET_ID.bat"
		author = "TheDFIRReport"
		reference = "https://thedfirreport.com/2024/04/01/from-onenote-to-ransomnote-an-ice-cold-intrusion"
		date = "2024-01-09"
		hash1 = "eae2bce6341ff7059b9382bfa0e0daa337ea9948dd729c0c1e1ee9c11c1c0068"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "for /f \"delims=\" %%i in ('C:\\ProgramData\\Any\\AnyDesk.exe --get-id') do set ID=%%i " fullword ascii
		$s2 = "echo AnyDesk ID is: %ID%" fullword ascii

	condition:
		uint16(0)==0x6540 and filesize <1KB and 1 of ($x*) and all of them
}
