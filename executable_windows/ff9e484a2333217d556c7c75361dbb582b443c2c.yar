import "pe"

rule IMPLANT_4_v11
{
	meta:
		description = "BlackEnergy / Voodoo Bear Implant by APT28"
		author = "US CERT"
		reference = "https://www.us-cert.gov/ncas/current-activity/2017/02/10/Enhanced-Analysis-GRIZZLY-STEPPE"
		date = "2017-02-10"
		score = 85
		os = "windows"
		filetype = "executable"

	strings:
		$ = "/c format %c: /Y /X /FS:NTFS"
		$ = ".exe.sys.drv.doc.docx.xls.xlsx.mdb.ppt.pptx.xml.jpg.jpeg.ini.inf.ttf" wide
		$ = ".dll.exe.xml.ttf.nfo.fon.ini.cfg.boot.jar" wide
		$ = ".crt.bin.exe.db.dbf.pdf.djvu.doc.docx.xls.xlsx.jar.ppt.pptx.tib.vhd.iso.lib.mdb.accdb.sql.mdf.xml.rtf.ini.cf g.boot.txt.rar.msi.zip.jpg.bmp.jpeg.tiff" wide
		$tempfilename = "%ls_%ls_%ls_%d.~tmp" ascii wide

	condition:
		( uint16(0)==0x5A4D or uint16(0)==0xCFD0 or uint16(0)==0xC3D4 or uint32(0)==0x46445025 or uint32(1)==0x6674725C) and 2 of them
}
