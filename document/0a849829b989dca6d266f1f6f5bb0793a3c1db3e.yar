rule MAL_RANSOM_Crime_DearCry_Mar2021_1
{
	meta:
		description = "Triggers on strings of known DearCry samples"
		author = "Nils Kuhnert"
		date = "2021-03-12"
		reference = "https://twitter.com/phillip_misner/status/1370197696280027136"
		hash1 = "2b9838da7edb0decd32b086e47a31e8f5733b5981ad8247a2f9508e232589bff"
		hash2 = "e044d9f2d0f1260c3f4a543a1e67f33fcac265be114a1b135fd575b860d2b8c6"
		hash3 = "feb3e6d30ba573ba23f3bd1291ca173b7879706d1fe039c34d53a4fdcdf33ede"
		os = "windows"
		filetype = "document"

	strings:
		$x1 = ".TIF .TIFF .PDF .XLS .XLSX .XLTM .PS .PPS .PPT .PPTX .DOC .DOCX .LOG .MSG .RTF .TEX .TXT .CAD .WPS .EML .INI .CSS .HTM .HTML  .XHTML .JS .JSP .PHP .KEYCHAIN .PEM .SQL .APK .APP .BAT .CGI .ASPX .CER .CFM .C .CPP .GO .CONFIG .PL .PY .DWG .XML .JPG .BMP .PNG .EXE .DLL .CAD .AVI .H.CSV .DAT .ISO .PST .PGD  .7Z .RAR .ZIP .ZIPX .TAR .PDB .BIN .DB .MDB .MDF .BAK .LOG .EDB .STM .DBF .ORA .GPG .EDB .MFS" ascii
		$s1 = "create rsa error" ascii fullword
		$s2 = "DEARCRY!" ascii fullword
		$s4 = "/readme.txt" ascii fullword
		$s5 = "msupdate" ascii fullword
		$s6 = "Your file has been encrypted!" ascii fullword
		$s7 = "%c:\\%s" ascii fullword
		$s8 = "C:\\Users\\john\\" ascii
		$s9 = "EncryptFile.exe.pdb" ascii

	condition:
		uint16(0)==0x5a4d and filesize >1MB and filesize <2MB and (1 of ($x*) or 3 of them ) or 5 of them
}
