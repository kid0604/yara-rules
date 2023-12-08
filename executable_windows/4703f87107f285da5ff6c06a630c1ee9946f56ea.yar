import "pe"

rule HvS_APT37_RAT_loader
{
	meta:
		description = "BLINDINGCAN RAT loader named iconcash.db used by APT37"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Marc Stroebel"
		date = "2020-12-15"
		hash = "b70e66d387e42f5f04b69b9eb15306036702ab8a50b16f5403289b5388292db9"
		reference1 = "https://www.hvs-consulting.de/media/downloads/ThreatReport-Lazarus.pdf"
		reference2 = "https://us-cert.cisa.gov/ncas/analysis-reports/ar20-232a"
		os = "windows"
		filetype = "executable"

	condition:
		(pe.version_info["OriginalFilename"] contains "MFC_DLL.dll") and (pe.exports("SMain") and pe.exports("SMainW"))
}
